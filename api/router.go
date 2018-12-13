package api

import (
	"fmt"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

func (a *API) initRouter() {
	// Create router
	a.Options.Router = mux.NewRouter().StrictSlash(true)
	// Logging middleware
	a.Options.Router.Use(a.loggingMiddleware)
	// Compression middleware
	a.Options.Router.Use(handlers.CompressHandler)
	// Proxy headers middleware
	a.Options.Router.Use(handlers.ProxyHeaders)
	// 404 handler
	a.Options.Router.NotFoundHandler = http.HandlerFunc(notFoundHandler404)
	// Method not allow handler
	a.Options.Router.MethodNotAllowedHandler = http.HandlerFunc(methodNotAllowed)
	// Initialize routes
	a.initRoutes()
}

func (a *API) initRoutes() {
	// Public Endpoints
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u",
		a.Options.Version), a.createUser).Methods("POST")

	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u/{username:[a-zA-Z0-9]+}",
		a.Options.Version), a.getUserFromUsername).Methods("GET")

	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u/{userId:[0-9]+}",
		a.Options.Version), a.getUserFromID).Methods("GET")

	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u",
		a.Options.Version), a.getAllUsers).Methods("GET")

	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u/login",
		a.Options.Version), a.login).Methods("POST")

	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/images",
		a.Options.Version), a.getAllImages).Methods("GET")

	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/images/{imageSlug:[a-z-]+}",
		a.Options.Version), a.getImage).Methods("GET")

	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/captions",
		a.Options.Version), a.getAllCaptions).Methods("GET")

	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/captions/{captionId:[0-9]+}",
		a.Options.Version), a.getCaption).Methods("GET")

	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/votes/{voteId:[0-9]+}",
		a.Options.Version), a.getVote).Methods("GET")

	// Handle User Requests
	a.Options.Router.Handle(fmt.Sprintf("/%s/u/{userId:[0-9]+}/refresh", a.Options.Version),
		negroni.New(negroni.HandlerFunc(refreshTokenMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.refreshAuthToken)))).Methods("GET")

	a.Options.Router.Handle(fmt.Sprintf("/%s/u/{userId:[0-9]+}/logout", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.logout)))).Methods("POST")

	a.Options.Router.Handle(fmt.Sprintf("/%s/u/{username:[a-zA-Z0-9]+}", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.deleteUser)))).Methods("DELETE")

	a.Options.Router.Handle(fmt.Sprintf("/%s/u/{username:[a-zA-Z0-9]+}", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.updateUser)))).Methods("PATCH")

	// Handle Image Requests
	a.Options.Router.Handle(fmt.Sprintf("/%s/images", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.createImage)))).Methods("POST")

	a.Options.Router.Handle(fmt.Sprintf("/%s/images/{imageSlug:[a-z-]+}", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.deleteImage)))).Methods("DELETE")

	a.Options.Router.Handle(fmt.Sprintf("/%s/images/{imageSlug:[a-z-]+}", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.updateImage)))).Methods("PATCH")

	// Handle Caption Requests
	a.Options.Router.Handle(fmt.Sprintf("/%s/captions", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.createCaption)))).Methods("POST")

	a.Options.Router.Handle(fmt.Sprintf("/%s/captions/{captionId:[0-9]+}", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.deleteCaption)))).Methods("DELETE")

	a.Options.Router.Handle(fmt.Sprintf("/%s/captions/{captionId:[0-9]+}", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.updateCaption)))).Methods("PATCH")

	// Handle Vote Requests
	a.Options.Router.Handle(fmt.Sprintf("/%s/votes", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.createVote)))).Methods("POST")

	a.Options.Router.Handle(fmt.Sprintf("/%s/votes/{voteId:[0-9]+}", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.deleteVote)))).Methods("DELETE")

	a.Options.Router.Handle(fmt.Sprintf("/%s/votes/{voteId:[0-9]+}", a.Options.Version),
		negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(a.updateVote)))).Methods("PATCH")
}

// Handles 404s
func notFoundHandler404(w http.ResponseWriter, r *http.Request) {
	respond(w, jsonResponse(http.StatusNotFound, "Invalid endpoint"))
}

// Handles invalid HTTP methods
func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	respond(w, jsonResponse(http.StatusMethodNotAllowed, "Method not allowed"))
}
