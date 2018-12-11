package pkg

import (
	"fmt"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"

	jwtmiddleware "github.com/ciehanski/go-jwt-middleware"
)

// jwtSigningKey is a global secret string for our token gathered from env
var jwtSigningKey = []byte(os.Getenv(JWTSecret))

// refreshSigningKey is a global secret string for our token gathered from env
var refreshSigningKey = []byte(os.Getenv(RefreshSecret))

// jwtMiddleware is a middleware handler for protected endpoints
var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		return jwtSigningKey, nil
	},
	CredentialsOptional: false,
	Extractor:           jwtmiddleware.FromCookie(AuthToken),
	Debug:               true,
	IgnoreExpiration:    false,
	SigningMethod:       jwt.SigningMethodHS256,
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		respond(w, jsonResponse(http.StatusInternalServerError, err.Error()))
	},
})

// refreshTokenMiddleware is a middleware handler for protected endpoints
var refreshTokenMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		return refreshSigningKey, nil
	},
	CredentialsOptional: false,
	Extractor:           jwtmiddleware.FromCookie(RefreshToken),
	Debug:               true,
	IgnoreExpiration:    false,
	SigningMethod:       jwt.SigningMethodHS256,
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		respond(w, jsonResponse(http.StatusInternalServerError, err.Error()))
	},
})

// loggingMiddleware is the middleware used to log each request sent to the api for debug purposes.
func (a *api) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the request details
		a.logf(fmt.Sprintf("%s %s %s %s", r.Proto, r.Method, r.RequestURI, getRemoteIP(r)))
		// Call the next handler
		next.ServeHTTP(w, r)
	})
}
