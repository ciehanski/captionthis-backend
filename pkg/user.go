package pkg

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
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
			w.WriteHeader(http.StatusNotFound)
			respond(w, jsonResponse(http.StatusNotFound, ErrRetrievingAllUsers.Error()))
			return
		}
		a.logf("Database error while getting all users: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrDatabase.Error()))
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
			w.WriteHeader(http.StatusNotFound)
			respond(w, jsonResponse(http.StatusNotFound, ErrUserNotFound.Error()))
			return
		}
		a.logf("Database error while getting %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrDatabase.Error()))
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
			w.WriteHeader(http.StatusNotFound)
			respond(w, jsonResponse(http.StatusNotFound, ErrUserNotFound.Error()))
			return
		}
		a.logf("Database error while getting %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrDatabase.Error()))
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
		a.logf("Bad request")
		w.WriteHeader(http.StatusBadRequest)
		respond(w, jsonResponse(http.StatusBadRequest, ErrBadRequest.Error()))
		return
	}

	// Validate the user
	if err := a.validateUser(user); err != nil {
		a.logf("Unable to validate user %s: %v", user.Username, err)
		w.WriteHeader(http.StatusConflict)
		respond(w, jsonResponse(http.StatusConflict, err.Error()))
		return
	}

	// Generate argon2 hash of the supplied password to store
	hashedPassword, hashErr := hashPassword(user.Password)
	if hashErr != nil {
		a.logf("Unable to generate random salt for %s's password: %v", user.Username, hashErr)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrCreateUser.Error()))
		return
	}

	// Store hashed password in database, never save the raw password
	user.Password = hashedPassword
	// Force lowercase email in database
	user.Email = strings.ToLower(user.Email)

	// Create the user
	if err := a.Options.DB.Create(&user).Error; err != nil {
		a.logf("Unable to create user %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrCreateUser.Error()))
		return
	}

	// Sanitize user's password
	user.Password = ""

	// Create JWT
	if err := a.createJWT(w, r, &user); err != nil {
		a.logf("Error creating JWTs for %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrCreatingTokens.Error()))
		return
	}

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
			w.WriteHeader(http.StatusNotFound)
			respond(w, jsonResponse(http.StatusNotFound, ErrUserNotFound.Error()))
			return
		}
		a.logf("Database error while getting %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrDatabase.Error()))
		return
	}

	// Sanitize user's password
	user.Password = ""

	// Decode user updates from POST
	var userUpdates User
	if err := json.NewDecoder(r.Body).Decode(&userUpdates); err != nil {
		a.logf("Bad request")
		w.WriteHeader(http.StatusBadRequest)
		respond(w, jsonResponse(http.StatusBadRequest, ErrBadRequest.Error()))
		return
	}

	// Validate the user updates
	if err := a.validateUser(userUpdates); err != nil {
		a.logf("Unable to validate user %s: %v", user.Username, err)
		w.WriteHeader(http.StatusConflict)
		respond(w, jsonResponse(http.StatusConflict, err.Error()))
		return
	}

	// Validate if the updater is actually the user being updated
	if err := validateIdentity(r, user); err != nil {
		a.logf("Unable to validate permissions to modify user %s: %v", user.Username, err)
		w.WriteHeader(http.StatusForbidden)
		respond(w, jsonResponse(http.StatusForbidden, ErrInvalidPermissionsToUpdate.Error()))
		return
	}

	// Only update the fields that were modified
	if err := a.Options.DB.Model(&user).Updates(userUpdates).Error; err != nil {
		a.logf("Unable to update user %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrUpdateUser.Error()))
		return
	}

	a.logf("User %s has been updated", user.Username)
	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("User %s successfully updated", username)))
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	username := params["username"]

	// Validate if the updater is actually the user being updated
	var user User
	if err := validateIdentity(r, user); err != nil {
		a.logf("Unable to validate permissions to modify user %s: %v", user.Username, err)
		w.WriteHeader(http.StatusForbidden)
		respond(w, jsonResponse(http.StatusForbidden, ErrInvalidPermissionsToUpdate.Error()))
		return
	}

	// Delete the user
	if err := a.Options.DB.Table("users").Where("username = ?", username).Delete(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", user.Username)
			w.WriteHeader(http.StatusNotFound)
			respond(w, jsonResponse(http.StatusNotFound, ErrUserNotFound.Error()))
			return
		}
		a.logf("Database error while deleting %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrDatabase.Error()))
		return
	}

	a.logf("User %s has been deleted", user.Username)
	respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("User %s successfully deleted", username)))
}

func (a *API) validateUser(user User) error {
	if err := a.Options.DB.Table("users").Where("username = ?", user.Username).First(&user).Error; err == nil {
		return ErrUsernameInUse
	}
	if err := a.Options.DB.Table("users").Where("email = ?", user.Email).First(&user).Error; err == nil {
		return ErrEmailInUse
	}
	validateCap := regexp.MustCompile(`[A-Z]+`)
	validateNum := regexp.MustCompile(`[0-9]+`)
	validateEmail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	validateSymbols := regexp.MustCompile(`[^\w\s]+`)
	switch {
	case validateSymbols.MatchString(user.Username):
		return ErrUsernameSymbols
	case !validateEmail.MatchString(user.Email):
		return ErrInvalidEmail
	case len(user.Password) < 8:
		return ErrPasswordTooShort
	case len(user.Password) > 100:
		return ErrPasswordTooLong
	case len(user.Username) < 3:
		return ErrUsernameTooShort
	case len(user.Username) > 20:
		return ErrUsernameTooLong
	case !validateSymbols.MatchString(user.Password):
		return ErrPasswordSymbol
	case !validateNum.MatchString(user.Password):
		return ErrPasswordNum
	case !validateCap.MatchString(user.Password):
		return ErrPasswordCapital
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
		return ErrInvalidTokenAndUser
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
		return ErrInvalidRefreshAndUser
	}

	return nil
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	// Decode POST
	var userReq User
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		a.logf("Bad request")
		w.WriteHeader(http.StatusBadRequest)
		respond(w, jsonResponse(http.StatusBadRequest, ErrBadRequest.Error()))
		return
	}

	// Does the user exist?
	var user User
	if err := a.Options.DB.Table("users").Where("username = ?", userReq.Username).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", user.Username)
			w.WriteHeader(http.StatusNotFound)
			respond(w, jsonResponse(http.StatusNotFound, ErrUserNotFound.Error()))
			return
		}
		a.logf("Database error while authenticating %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrDatabase.Error()))
		return
	}

	// Check password with stored hash
	if ok, err := comparePasswordHash(user.Password, userReq.Password); !ok {
		a.logf("Incorrect password entered for %s", user.Username)
		w.WriteHeader(http.StatusUnauthorized)
		respond(w, jsonResponse(http.StatusUnauthorized, ErrIncorrectPassword.Error()))
		return
	} else if err != nil {
		a.logf("Error comparing hash and password for %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrValidatingPassword.Error()))
		return
	}

	// Sanitize user's password
	user.Password = ""

	// Create JWT
	if err := a.createJWT(w, r, &user); err != nil {
		a.logf("Error creating JWTs for %s: %v", user.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrCreatingTokens.Error()))
		return
	}

	// Send back user info in response
	resp := jsonResponse(http.StatusOK, fmt.Sprintf("User %s authenticated", user.Username))
	resp["user"] = user

	a.logf("User %s has been logged in", user.Username)
	respond(w, resp)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	authCookie, err := r.Cookie(AuthToken)
	if err != nil {
		a.logf("Unable to get auth cookie: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrLoggingOut.Error()))
		return
	} else {
		authCookie.Value = ""
		authCookie.MaxAge = -1
		authCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
		http.SetCookie(w, authCookie)
	}

	refreshCookie, err := r.Cookie(RefreshToken)
	if err != nil {
		a.logf("Unable to get refresh cookie: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrLoggingOut.Error()))
		return
	} else {
		refreshCookie.Value = ""
		refreshCookie.MaxAge = -1
		refreshCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
		http.SetCookie(w, refreshCookie)
	}

	userCookie, err := r.Cookie(UserToken)
	if err != nil {
		a.logf("Unable to get user cookie: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrLoggingOut.Error()))
		return
	} else {
		userCookie.Value = ""
		userCookie.MaxAge = -1
		userCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
		http.SetCookie(w, userCookie)
	}

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
		a.logf("Unable to get token cookie: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrReauthenticate.Error()))
		return
	}
	refreshTok, err := jwt.Parse(refreshCookie.Value,
		func(*jwt.Token) (interface{}, error) {
			return refreshSigningKey, nil
		})
	if err != nil {
		a.logf("Error parsing refresh token %s: %v", refreshTok.Raw, err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrReauthenticate.Error()))
		return
	}

	// Validate supplied userId matches the user ID of the refresh token and user cookie
	if userID != refreshTok.Claims.(jwt.MapClaims)["sub"] {
		a.logf("Params userId %s does not match refresh token userId %s",
			userID, refreshTok.Claims.(jwt.MapClaims)["sub"])
		w.WriteHeader(http.StatusUnauthorized)
		respond(w, jsonResponse(http.StatusUnauthorized, ErrReauthenticate.Error()))
		return
	}
	userCookie, err := r.Cookie(UserToken)
	if err != nil {
		a.logf("Unable to get user cookie: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrReauthenticate.Error()))
		return
	}
	userTok, err := jwt.Parse(userCookie.Value,
		func(*jwt.Token) (interface{}, error) {
			return jwtSigningKey, nil
		})
	if refreshTok.Claims.(jwt.MapClaims)["sub"].(int) != userTok.Claims.(jwt.MapClaims)["sub"].(int) {
		a.logf("Refresh token userId %s does not match user cookie userId %s",
			refreshTok.Claims.(jwt.MapClaims)["sub"], userTok.Claims.(jwt.MapClaims)["sub"])
		w.WriteHeader(http.StatusUnauthorized)
		respond(w, jsonResponse(http.StatusUnauthorized, ErrReauthenticate.Error()))
		return
	}

	// Everything is valid, create JWT
	token := jwt.New(jwt.SigningMethodHS256)
	jti, err := uuid.NewV4()
	if err != nil {
		a.logf("Unable to generate UUID for token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrReauthenticate.Error()))
		return
	}
	// Set token claims
	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = jti
	claims["iss"] = jwtIss
	claims["aud"] = jwtAud
	claims["sub"] = userID
	claims["nbf"] = time.Now().Unix()
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	signedToken, err := token.SignedString(jwtSigningKey)
	if err != nil {
		a.logf("Unable to sign token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, ErrReauthenticate.Error()))
		return
	}

	// JWT token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     AuthToken,
		Domain:   CookieDomain,
		SameSite: http.SameSiteStrictMode,
		Value:    signedToken,
		Path:     CookiePath,
		Expires:  time.Now().Add(time.Minute * 15),
		HttpOnly: true,
		Secure:   !a.Options.Debug,
	})

	a.logf("Auth token refreshed for %v", userID)
	respond(w, jsonResponse(http.StatusOK, "User token has been refreshed"))
}

// createToken creates a jwt token with user claims
func (a *API) createJWT(w http.ResponseWriter, r *http.Request, user *User) error {
	// Create JWT
	token := jwt.New(jwt.SigningMethodHS256)
	jti, err := uuid.NewV4()
	if err != nil {
		return err
	}
	// Set token claims
	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = jti
	claims["iss"] = jwtIss
	claims["aud"] = jwtAud
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
	refreshClaims["iss"] = jwtIss
	refreshClaims["aud"] = jwtAud
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
	userClaims["iss"] = jwtIss
	userClaims["aud"] = jwtAud
	userClaims["sub"] = user.ID
	userClaims["username"] = user.Username
	userClaims["email"] = user.Email
	userClaims["emailconfirmed"] = user.EmailConfirmed
	userClaims["nbf"] = time.Now().Unix()
	userClaims["iat"] = time.Now().Unix()
	userClaims["exp"] = time.Now().Unix()
	signedUserToken, err := userToken.SignedString(userSigningKey)
	if err != nil {
		return err
	}

	// JWT token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     AuthToken,
		Domain:   CookieDomain,
		SameSite: http.SameSiteStrictMode,
		Value:    signedToken,
		Path:     CookiePath,
		MaxAge:   900,
		Expires:  time.Now().Add(time.Minute * 15),
		HttpOnly: true,
		Secure:   !a.Options.Debug,
	})

	// Refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshToken,
		Domain:   CookieDomain,
		SameSite: http.SameSiteStrictMode,
		Value:    signedRefreshToken,
		Path:     CookiePath,
		HttpOnly: true,
		Secure:   !a.Options.Debug,
	})

	// User token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     UserToken,
		Domain:   CookieDomain,
		SameSite: http.SameSiteStrictMode,
		Value:    signedUserToken,
		Path:     CookiePath,
		HttpOnly: false,
		Secure:   !a.Options.Debug,
	})

	a.logf("JWTs and cookies created for %s", user.Username)
	return nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	passwordHash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	// Base64 encode the salt and hashed password
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(passwordHash)
	// Return a string using the standard encoded hash representation
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads, b64Salt, b64Hash), nil
}

func comparePasswordHash(expectedPassword, providedPassword string) (bool, error) {
	vals := strings.Split(expectedPassword, "$")
	if len(vals) != 6 {
		return false, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, ErrWrongArgonVersion
	}

	var mem, iter uint32
	var thread uint8
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &mem, &iter, &thread)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return false, err
	}

	actualPasswordHash, err := base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return false, err
	}

	providedPasswordHash := argon2.IDKey([]byte(providedPassword), salt, iter, mem, thread, uint32(len(actualPasswordHash)))
	return subtle.ConstantTimeCompare(actualPasswordHash, providedPasswordHash) == 1, nil
}
