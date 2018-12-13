package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/argon2"
)

func (a *API) getAllUsers(w http.ResponseWriter, r *http.Request) {
	var users []User

	if err := a.Options.DB.Find(&users).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("Unable to retrieve all users")
			respond(w, jsonResponse(http.StatusNotFound, "Unable to retrieve all users"))
			return
		}
		a.logf("Database error while getting all users: %s", err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Database error"))
		return
	}

	// TODO: secure?
	// Sanitize users' passwords
	for i := range users {
		users[i].Password = ""
	}

	a.logf("All users retrieved")
	respond(w, users)
}

func (a *API) getUserFromUsername(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	username := params["username"]
	var user User

	if err := a.Options.DB.Table("users").Where("username = ?", username).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", user.Username)
			respond(w, jsonResponse(http.StatusNotFound, "User not found"))
			return
		}
		a.logf("Database error while getting %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Database error"))
		return
	}

	// Sanitize user's password
	user.Password = ""

	a.logf("User %s retrieved by username", user.Username)
	respond(w, user)
}

func (a *API) getUserFromID(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["userId"]
	var user User

	if err := a.Options.DB.Table("users").Where("id = ?", id).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", user.Username)
			respond(w, jsonResponse(http.StatusNotFound, "User not found"))
			return
		}
		a.logf("Database error while getting %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Database error"))
		return
	}

	// Sanitize user's password
	user.Password = ""

	a.logf("User %s retrieved by ID", user.Username)
	respond(w, user)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var user User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		a.logf("Bad request: %s", err.Error())
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	// Validate the user
	if err := a.validateUser(user); err != nil {
		a.logf("Unable to validate user %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusConflict, err.Error()))
		return
	}

	// Generate argon2 hash of the supplied password to store
	hashedPassword, hashErr := hashPassword(user.Password)
	if hashErr != nil {
		a.logf("Unable to generate random salt for %s's password: %s", user.Username, hashErr.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Unable to create user"))
		return
	}

	// Store hashed password in database, never save the raw password
	user.Password = hashedPassword
	// Force lowercase email in database
	user.Email = strings.ToLower(user.Email)

	// Create the user
	if err := a.Options.DB.Create(&user).Error; err != nil {
		a.logf("Unable to create user %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Unable to create user"))
		return
	}

	// Sanitize user's password with dummy password
	user.Password = ""

	// Create JWT
	if err := a.createJWT(w, &user); err != nil {
		a.logf("Error creating JWTs for %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error creating authentication token"))
		return
	}

	// Allow cookies to be saved to the browser
	w.Header().Add("Access-Control-Allow-Credentials", "true")

	// Send back response
	resp := jsonResponse(http.StatusCreated, fmt.Sprintf("User %s created", user.Username))
	resp["user"] = user

	a.logf("User %s created", user.Username)
	respond(w, resp)
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	username := params["username"]

	var user User
	if err := a.Options.DB.Table("users").Where("username = ?", username).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", user.Username)
			respond(w, jsonResponse(http.StatusNotFound, "User not found"))
			return
		}
		a.logf("Database error while getting %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Database error"))
		return
	}

	// Sanitize user's password
	user.Password = ""

	// Decode user updates from POST
	var userUpdates User
	if err := json.NewDecoder(r.Body).Decode(&userUpdates); err != nil {
		a.logf("Bad request: %s", err.Error())
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	// Validate the user updates
	if err := a.validateUser(userUpdates); err != nil {
		a.logf("Unable to validate user %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusConflict, err.Error()))
		return
	}

	// Validate if the updater is actually the user being updated
	if err := validateIdentity(r, user); err != nil {
		a.logf("Unable to validate permissions to modify user %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusForbidden, "Invalid permissions to update user"))
		return
	}

	// Only update the fields that were modified
	if err := a.Options.DB.Model(&user).Updates(userUpdates).Error; err != nil {
		a.logf("Unable to update user %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Unable to update user"))
		return
	}

	a.logf("User %s has been updated", user.Username)
	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("User %s successfully updated", username)))
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	username := params["username"]
	var user User

	// Validate if the updater is actually the user being updated
	if err := validateIdentity(r, user); err != nil {
		a.logf("Unable to validate permissions to modify user %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusForbidden, "Invalid permissions to update user"))
		return
	}

	// Delete the user
	if err := a.Options.DB.Table("users").Where("username = ?", username).Delete(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", user.Username)
			respond(w, jsonResponse(http.StatusNotFound, "User not found"))
			return
		}
		a.logf("Database error while deleting %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Database error"))
		return
	}

	a.logf("User %s has been deleted", user.Username)
	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("User %s successfully deleted", username)))
}

func (a *API) validateUser(user User) error {
	if err := a.Options.DB.Table("users").Where("username = ?", user.Username).First(&user).Error; err == nil {
		return errors.New("Username already in use")
	}
	if err := a.Options.DB.Table("users").Where("email = ?", user.Email).First(&user).Error; err == nil {
		return errors.New("Email already in use")
	}
	validateCap := regexp.MustCompile(`[A-Z]+`)
	validateNum := regexp.MustCompile(`[0-9]+`)
	validateEmail := regexp.MustCompile(
		"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	validateSymbols := regexp.MustCompile(`[^\w\s]+`)
	switch {
	case validateSymbols.MatchString(user.Username):
		return errors.New("Username cannot contain symbols")
	case !validateEmail.MatchString(user.Email):
		return errors.New("Invalid email address")
	case len(user.Password) < 8:
		return errors.New("Password must contain at least 8 characters")
	case len(user.Password) > 100:
		return errors.New("Password cannot exceed 100 characters")
	case len(user.Username) < 3:
		return errors.New("Username must contain at least 3 characters")
	case len(user.Username) > 20:
		return errors.New("Username cannot exceed 20 characters")
	case !validateSymbols.MatchString(user.Password):
		return errors.New("Password must contain at least one symbol")
	case !validateNum.MatchString(user.Password):
		return errors.New("Password must contain at least one number")
	case !validateCap.MatchString(user.Password):
		return errors.New("Password must contain at least one capital character")
	default:
		return nil
	}
}

func validateIdentity(r *http.Request, user User) error {
	// Grab user cookie and parse it
	userCookie, err := r.Cookie(UserToken)
	if err != nil {
		return err
	}
	userTok, err := jwt.Parse(userCookie.Value,
		func(*jwt.Token) (interface{}, error) {
			return jwtSigningKey, nil
		})
	if err != nil {
		return err
	}
	if userTok.Claims.(jwt.MapClaims)["sub"] != user.ID {
		return errors.New("user token does not match user ID provided")
	}

	// Grab refresh cookie and parse it
	refreshCookie, err := r.Cookie(RefreshToken)
	if err != nil {
		return err
	}
	refreshTok, err := jwt.Parse(refreshCookie.Value,
		func(*jwt.Token) (interface{}, error) {
			return refreshSigningKey, nil
		})
	if err != nil {
		return err
	}
	if refreshTok.Claims.(jwt.MapClaims)["sub"] != user.ID {
		return errors.New("refresh token does not match user ID provided")
	}

	return nil
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	// Decode POST
	var userReq User
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		a.logf("Bad request: %s", err.Error())
		respond(w, jsonResponse(http.StatusBadRequest, "Bad request"))
		return
	}

	// Does the user exist?
	var user User
	if err := a.Options.DB.Table("users").Where("username = ?", userReq.Username).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", user.Username)
			respond(w, jsonResponse(http.StatusNotFound, "User not found"))
			return
		}
		a.logf("Database error while authenticating %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Database error"))
		return
	}

	// Check password with stored hash
	if ok, err := comparePasswordHash(user.Password, userReq.Password); !ok {
		a.logf("Incorrect password entered for %s", user.Username)
		respond(w, jsonResponse(http.StatusUnauthorized, "Incorrect password"))
		return
	} else if err != nil {
		a.logf("Error comparing hash and password for %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error validating password"))
		return
	}

	// Sanitize user's password
	user.Password = ""

	// Create JWT
	if err := a.createJWT(w, &user); err != nil {
		a.logf("Error creating JWTs for %s: %s", user.Username, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error creating authentication token"))
		return
	}

	// Allow cookies to be saved to the browser
	w.Header().Add("Access-Control-Allow-Credentials", "true")

	// Send back user info in response
	resp := jsonResponse(http.StatusOK, fmt.Sprintf("User %s authenticated", user.Username))
	resp["user"] = user

	a.logf("User %s has been logged in", user.Username)
	respond(w, resp)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	authCookie, err := r.Cookie(AuthToken)
	if err != nil {
		a.logf("Unable to get auth cookie: %s", err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error logging user out"))
		return
	}
	authCookie.Value = ""
	authCookie.Path = "/"
	authCookie.MaxAge = -1
	authCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
	http.SetCookie(w, authCookie)

	refreshCookie, err := r.Cookie(RefreshToken)
	if err != nil {
		a.logf("Unable to get refresh cookie: %s", err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error logging user out"))
		return
	}
	refreshCookie.Value = ""
	refreshCookie.Path = "/"
	refreshCookie.MaxAge = -1
	refreshCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
	http.SetCookie(w, refreshCookie)

	userCookie, err := r.Cookie(UserToken)
	if err != nil {
		a.logf("Unable to get user cookie: %s", err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error logging user out"))
		return
	}
	userCookie.Value = ""
	userCookie.Path = "/"
	userCookie.MaxAge = -1
	userCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
	http.SetCookie(w, userCookie)

	// Allow cookies to be saved to the browser
	w.Header().Add("Access-Control-Allow-Credentials", "true")

	a.logf("User has been logged out")
	respond(w, jsonResponse(http.StatusOK, "User has been logged out"))
}

func (a *API) refreshAuthToken(w http.ResponseWriter, r *http.Request) {
	// Grab URL params
	params := mux.Vars(r)
	userID := params["userId"]

	// Grab refresh cookie and parse it
	refreshCookie, err := r.Cookie(RefreshToken)
	if err != nil {
		a.logf("Unable to get authToken cookie: %s", err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error re-authenticating"))
		return
	}
	refreshTok, err := jwt.Parse(refreshCookie.Value,
		func(*jwt.Token) (interface{}, error) {
			return refreshSigningKey, nil
		})
	if err != nil {
		a.logf("Error parsing refresh token %s: %s", refreshTok.Raw, err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error re-authenticating"))
		return
	}

	// Validate supplied userId matches the user ID of the refresh token and user cookie
	if userID != refreshTok.Claims.(jwt.MapClaims)["sub"] {
		a.logf("Params userId %s does not match refresh token userId %s", userID, refreshTok.Claims.(jwt.MapClaims)["sub"])
		respond(w, jsonResponse(http.StatusUnauthorized, "Error re-authenticating"))
		return
	}
	userCookie, err := r.Cookie(UserToken)
	if err != nil {
		a.logf("Unable to get user cookie: %s", err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error re-authenticating"))
		return
	}
	userTok, err := jwt.Parse(userCookie.Value,
		func(*jwt.Token) (interface{}, error) {
			return jwtSigningKey, nil
		})
	if refreshTok.Claims.(jwt.MapClaims)["sub"] != userTok.Claims.(jwt.MapClaims)["sub"] {
		a.logf("Refresh token userId %s does not match user cookie userId %s",
			refreshTok.Claims.(jwt.MapClaims)["sub"], userTok.Claims.(jwt.MapClaims)["sub"])
		respond(w, jsonResponse(http.StatusUnauthorized, "Error re-authenticating"))
		return
	}

	// Everything is valid, create JWT
	token := jwt.New(jwt.SigningMethodHS256)
	jti, err := uuid.NewV4()
	if err != nil {
		a.logf("Unable to generate UUID for token: %s", err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error re-authenticating"))
		return
	}
	// Set token claims
	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = jti
	claims["iss"] = captionthisBackend
	claims["aud"] = captionthisFrontend
	claims["sub"] = userID
	claims["nbf"] = time.Now().Unix()
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	signedToken, err := token.SignedString(jwtSigningKey)
	if err != nil {
		a.logf("Unable to sign token: %s", err.Error())
		respond(w, jsonResponse(http.StatusInternalServerError, "Error re-authenticating"))
		return
	}

	// JWT token in cookie
	authCookie := &http.Cookie{
		Name: AuthToken,
		//Domain:   "captionthis.io",
		SameSite: http.SameSiteStrictMode,
		Value:    signedToken,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute * 15),
		HttpOnly: true,
		Secure:   !a.Options.Debug,
	}
	http.SetCookie(w, authCookie)

	// Allow cookies to be saved to the browser
	w.Header().Add("Access-Control-Allow-Credentials", "true")

	a.logf("Auth token refreshed for %v", userID)
	respond(w, jsonResponse(http.StatusOK, "User token has been refreshed"))
}

// createToken creates a jwt token with user claims
func (a *API) createJWT(w http.ResponseWriter, user *User) error {
	// Create JWT
	token := jwt.New(jwt.SigningMethodHS256)
	jti, err := uuid.NewV4()
	if err != nil {
		return err
	}
	// Set token claims
	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = jti
	claims["iss"] = captionthisBackend
	claims["aud"] = captionthisFrontend
	claims["sub"] = user.ID
	claims["nbf"] = time.Now().Unix()
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	signedToken, err := token.SignedString(jwtSigningKey)
	if err != nil {
		return err
	}

	// Create refresh token
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshJti, err := uuid.NewV4()
	if err != nil {
		return err
	}
	// Set token claims
	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshClaims["jti"] = refreshJti
	refreshClaims["iss"] = captionthisBackend
	refreshClaims["aud"] = captionthisFrontend
	refreshClaims["sub"] = user.ID
	refreshClaims["nbf"] = time.Now().Unix()
	refreshClaims["iat"] = time.Now().Unix()
	refreshClaims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	signedRefreshToken, err := refreshToken.SignedString(refreshSigningKey)
	if err != nil {
		return err
	}

	// Create refresh token
	userToken := jwt.New(jwt.SigningMethodHS256)
	userJTI, err := uuid.NewV4()
	if err != nil {
		return err
	}
	// Set token claims
	userClaims := userToken.Claims.(jwt.MapClaims)
	userClaims["jti"] = userJTI
	userClaims["iss"] = captionthisBackend
	userClaims["aud"] = captionthisFrontend
	userClaims["sub"] = user.ID
	userClaims["username"] = user.Username
	userClaims["email"] = user.Email
	userClaims["emailconfirmed"] = user.EmailConfirmed
	userClaims["nbf"] = time.Now().Unix()
	userClaims["iat"] = time.Now().Unix()
	userClaims["exp"] = time.Now().Unix()
	signedUserToken, err := userToken.SignedString(jwtSigningKey)
	if err != nil {
		return err
	}

	// JWT token in cookie
	authCookie := &http.Cookie{
		Name: AuthToken,
		//Domain:   "captionthis.io",
		SameSite: http.SameSiteStrictMode,
		Value:    signedToken,
		Path:     "/",
		MaxAge:   900,
		Expires:  time.Now().Add(time.Minute * 15),
		HttpOnly: true,
		Secure:   !a.Options.Debug,
	}
	http.SetCookie(w, authCookie)

	// Refresh token cookie
	refreshCookie := &http.Cookie{
		Name: RefreshToken,
		//Domain:   "captionthis.io",
		SameSite: http.SameSiteStrictMode,
		Value:    signedRefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   !a.Options.Debug,
	}
	http.SetCookie(w, refreshCookie)

	// User token cookie
	userCookie := &http.Cookie{
		Name: UserToken,
		//Domain:   "captionthis.io",
		SameSite: http.SameSiteStrictMode,
		Value:    signedUserToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   !a.Options.Debug,
	}
	http.SetCookie(w, userCookie)

	a.logf("JWTs and cookies created for %s", user.Username)
	return nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	passwordHash := argon2.Key([]byte(password), salt, 3, 32*1024, 4, 32)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(passwordHash), nil
}

func comparePasswordHash(expectedPassword, providedPassword string) (bool, error) {
	passwordSeg := strings.Split(expectedPassword, ":")
	salt, err := hex.DecodeString(passwordSeg[0])
	if err != nil {
		return false, err
	}
	actualPasswordHash, err := hex.DecodeString(passwordSeg[1])
	if err != nil {
		return false, err
	}
	providedPasswordHash := argon2.Key([]byte(providedPassword), salt, 3, 32*1024, 4, 32)
	return subtle.ConstantTimeCompare(actualPasswordHash, providedPasswordHash) == 1, nil
}
