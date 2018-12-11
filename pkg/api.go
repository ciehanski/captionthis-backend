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

	newAPI := api{Options: opts}

	if err := newAPI.initDB(); err != nil {
		return nil, err
	}

	newAPI.initRouter()
	if err := newAPI.initCaching(); err != nil {
		return nil, err
	}

	return &newAPI, nil
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
		return nil
	}

	a.Options.DB.AutoMigrate(User{}, Image{}, Caption{}, Vote{})

	return nil
}

func (a *api) CloseDB() error {
	if a.Options.DB != nil {
		if err := a.Options.DB.Close(); err != nil {
			return fmt.Errorf("error closing connection to database: %s", err.Error())
		}
	}
	return nil
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

// Handles 404s
func notFoundHandler404(w http.ResponseWriter, r *http.Request) {
	respond(w, jsonResponse(http.StatusNotFound, "Invalid endpoint"))
}

// Handles invalid HTTP methods
func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	respond(w, jsonResponse(http.StatusMethodNotAllowed, "Method not allowed"))
}
