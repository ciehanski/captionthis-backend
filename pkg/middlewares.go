package pkg

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/ciehanski/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
)

var (
	// jwtSigningKey is a global secret string for our token gathered from env
	jwtSigningKey = []byte(os.Getenv(JWTSecretENV))
	// refreshSigningKey is a global secret string for our refresh token gathered from env
	refreshSigningKey = []byte(os.Getenv(RefreshSecretENV))
	// userSigningKey is a global secret string for our user cookie gathered from env
	userSigningKey = []byte(os.Getenv(UserENV))
)

// jwtMiddleware is a middleware handler for protected endpoints
var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		return jwtSigningKey, nil
	},
	CredentialsOptional: false,
	Extractor:           jwtmiddleware.FromCookie(AuthToken),
	Debug:               true,
	UserProperty:        UserContext,
	SigningMethod:       jwt.SigningMethodHS256,
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusInternalServerError)
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
	UserProperty:        UserContext,
	SigningMethod:       jwt.SigningMethodHS256,
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusInternalServerError)
		respond(w, jsonResponse(http.StatusInternalServerError, err.Error()))
	},
})

// loggingMiddleware is the middleware used to log each request sent to the API for debug purposes.
func (a *API) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the request details
		a.logf("\n%s %s %s\nHost: %s\nUser Agent: %s %s\n", r.Method, r.RequestURI,
			r.Proto, r.Host, r.UserAgent(), getRemoteIP(r))
		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// getRemoteIP is a helper function that retrieves the remote IP address of the requesting HTTP-client.
func getRemoteIP(r *http.Request) string {
	// Get the X-Forwarded-For header, if present.
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	// No forwarded IP?  Then use the remote address directly.
	if xForwardedFor == "" {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return ip
	}
	entries := strings.Split(xForwardedFor, ",")
	addr := strings.TrimSpace(entries[0])
	return addr
}

// Recover is a middleware that recovers from panics that occur for a request.
func recoverMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					http.Error(w, fmt.Sprintf("[PANIC RECOVERED] %v", err), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
