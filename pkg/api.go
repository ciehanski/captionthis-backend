package pkg

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	cache "github.com/victorspringer/http-cache"
	"github.com/victorspringer/http-cache/adapter/memory"
)

func New(options ...Options) (*api, error) {
	var opts Options
	if len(options) > 0 {
		opts = options[0]
	}

	if opts.Version == "" {
		opts.Version = "v1"
	}
	if opts.DBname == "" || opts.DBpass == "" || opts.DBuser == "" || opts.DBhost == "" {
		return nil, errors.New("database information must not be nil")
	}

	api := &api{
		Options: opts,
	}
	if err := api.initDB(); err != nil {
		return nil, err
	}
	api.initRouter()
	if err := api.initCaching(); err != nil {
		return nil, err
	}

	return api, nil
}

func (a *api) Run(addr string) error {
	// Define http server
	// Best practice to set timeouts to avoid Slowloris attacks.
	srv := &http.Server{
		Addr:         addr,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      a.Options.Router,
	}

	// Start HTTP Server
	fmt.Println(fmt.Sprintf("captionthis API listening at: %s/%s", addr, a.Options.Version))

	return srv.ListenAndServe()
}

// logf prints application errors if debug is enabled
func (a *api) logf(format string, args ...interface{}) {
	if a.Options.Debug {
		log.Printf(format, args...)
	}
}

func (a *api) initDB() error {
	// Database parameters
	dbURI := fmt.Sprintf("host=%s user=%s dbname=%s password=%s sslmode=%s", a.Options.DBhost, a.Options.DBuser,
		a.Options.DBname, a.Options.DBpass, a.Options.DBssl)

	// Connect to the database
	var err error
	if a.Options.DB, err = gorm.Open("postgres", dbURI); err != nil {
		return err
	}

	// Enable pooling
	// ref: https://github.com/jinzhu/gorm/issues/246
	a.Options.DB.DB().SetMaxIdleConns(0)
	a.Options.DB.DB().SetMaxOpenConns(0)

	// Double-check we can ping the DB after it connects
	if err = a.Options.DB.DB().Ping(); err != nil {
		return err
	}

	// Auto migrate database based on the model structs below
	if a.Options.Debug {
		a.Options.DB.Debug().AutoMigrate(User{}, Image{}, Caption{}, Vote{})
	} else {
		a.Options.DB.AutoMigrate(User{}, Image{}, Caption{}, Vote{})
	}

	return nil
}

func (a *api) CloseDB() {
	err := a.Options.DB.Close()
	if err != nil {
		log.Fatalf("Error closing connection to database: %s", err.Error())
	}
}

func (a *api) initCaching() error {
	// Create the in-memory cache store
	memcached, err := memory.NewAdapter(
		memory.AdapterWithAlgorithm(memory.LRU),
		memory.AdapterWithCapacity(1000000),
	)
	if err != nil {
		return err
	}

	// Create the caching client which enables middleware usage
	cacheClient, err := cache.NewClient(
		cache.ClientWithAdapter(memcached),
		cache.ClientWithTTL(10*time.Minute),
	)
	if err != nil {
		return err
	}

	a.Options.Router.Use(cacheClient.Middleware)
	return nil
}

func (a *api) initRouter() {
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

func (a *api) initRoutes() {
	// Public Endpoints
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u", a.Options.Version), a.createUser).Methods("POST")
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u/{username:[a-zA-Z0-9]+}", a.Options.Version), a.getUserFromUsername).Methods("GET")
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u/{userId:[0-9]+}", a.Options.Version), a.getUserFromID).Methods("GET")
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u", a.Options.Version), a.getAllUsers).Methods("GET")
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/u/login", a.Options.Version), a.login).Methods("POST")
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/images", a.Options.Version), a.getAllImages).Methods("GET")
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/images/{imageSlug:[a-z-]+}", a.Options.Version), a.getImage).Methods("GET")
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/captions", a.Options.Version), a.getAllCaptions).Methods("GET")
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/captions/{captionId:[0-9]+}", a.Options.Version), a.getCaption).Methods("GET")
	a.Options.Router.HandleFunc(fmt.Sprintf("/%s/votes/{voteId:[0-9]+}", a.Options.Version), a.getVote).Methods("GET")

	// Handle User Requests
	a.Options.Router.Handle(fmt.Sprintf("/%s/u/{userId:[0-9]+}/refresh", a.Options.Version), negroni.New(negroni.HandlerFunc(refreshTokenMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.refreshAuthToken)))).Methods("GET")
	a.Options.Router.Handle(fmt.Sprintf("/%s/u/{userId:[0-9]+}/logout", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.logout)))).Methods("GET")
	a.Options.Router.Handle(fmt.Sprintf("/%s/u/{username:[a-zA-Z0-9]+}", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.deleteUser)))).Methods("DELETE")
	a.Options.Router.Handle(fmt.Sprintf("/%s/u/{username:[a-zA-Z0-9]+}", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.updateUser)))).Methods("PATCH")

	// Handle Image Requests
	a.Options.Router.Handle(fmt.Sprintf("/%s/images", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.createImage)))).Methods("POST")
	a.Options.Router.Handle(fmt.Sprintf("/%s/images/{imageSlug:[a-z-]+}", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.deleteImage)))).Methods("DELETE")
	a.Options.Router.Handle(fmt.Sprintf("/%s/images/{imageSlug:[a-z-]+}", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.updateImage)))).Methods("PATCH")

	// Handle Caption Requests
	a.Options.Router.Handle(fmt.Sprintf("/%s/captions", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.createCaption)))).Methods("POST")
	a.Options.Router.Handle(fmt.Sprintf("/%s/captions/{captionId:[0-9]+}", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.deleteCaption)))).Methods("DELETE")
	a.Options.Router.Handle(fmt.Sprintf("/%s/captions/{captionId:[0-9]+}", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.updateCaption)))).Methods("PATCH")

	// Handle Vote Requests
	a.Options.Router.Handle(fmt.Sprintf("/%s/votes", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.createVote)))).Methods("POST")
	a.Options.Router.Handle(fmt.Sprintf("/%s/votes/{voteId:[0-9]+}", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(a.deleteVote)))).Methods("DELETE")
	a.Options.Router.Handle(fmt.Sprintf("/%s/votes/{voteId:[0-9]+}", a.Options.Version), negroni.New(negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
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
