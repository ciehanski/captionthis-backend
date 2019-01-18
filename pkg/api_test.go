package pkg

import (
	"fmt"
	"os"
	"testing"
)

var TestAPI *API

func init() {
	var err error
	TestAPI, err = New(Options{
		DBhost: os.Getenv("dbhost"),
		DBname: os.Getenv("dbname"),
		DBuser: os.Getenv("dbuser"),
		DBpass: os.Getenv("dbpass"),
		DBssl:  os.Getenv("dbssl"),
	})
	if err != nil {
		return
	}
}

func TestNew(t *testing.T) {
	a, err := New(Options{
		DBhost: os.Getenv("dbhost"),
		DBname: os.Getenv("dbname"),
		DBuser: os.Getenv("dbuser"),
		DBpass: os.Getenv("dbpass"),
		DBssl:  os.Getenv("dbssl"),
	})
	if err != nil {
		t.Error(err)
	}
	// Test init router
	if a.Options.Router == nil {
		t.Error("Router was not properly initialized")
	}
	// Test blank version
	if a.Options.Version != "v1" {
		t.Error("Expected default version of 'v1' since version was not defined")
	}
	// Test blank addr
	if a.Options.Addr != "127.0.0.1:8080" {
		t.Error("Expected default addr of '127.0.0.1:8080' since addr was not defined")
	}
	// Test init db
	if a.Options.DB == nil {
		t.Error("Database was not properly initialized")
	}
	// Test init logger
	if a.Options.Logger == nil {
		t.Error("Logger was not properly initialized")
	}
}

func TestRun(t *testing.T) {
	// TODO: fix, test never stops running
	t.Skip()
	err := TestAPI.Run()
	if err != nil {
		t.Error(fmt.Sprintf("Error starting server: %v", err))
	}
}
