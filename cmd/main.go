package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/ciehanski/captionthis-backend/pkg"
)

func main() {
	a, err := pkg.New(pkg.Options{
		Addr:    os.Getenv("addr"),
		Version: "v1beta",
		DBhost:  os.Getenv("dbhost"),
		DBname:  os.Getenv("dbname"),
		DBuser:  os.Getenv("dbuser"),
		DBpass:  os.Getenv("dbpass"),
		DBssl:   os.Getenv("dbssl"),
		Debug:   true,
	})
	if err != nil {
		a.Options.Logger.Fatalf("Error initializing API: %v", err)
		os.Exit(pkg.ErrInitilizing)
	}

	// Gracefully defer close connection to database
	defer func() {
		if err := a.Options.DB.Close(); err != nil {
			a.Options.Logger.Panicf("Error closing connection to database: %v", err)
			os.Exit(pkg.ErrClosingDatabase)
		}
	}()

	// Handle server interrupts
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		a.Options.Logger.Println("Server is shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), a.Options.Server.WriteTimeout)
		defer cancel()

		a.Options.Server.SetKeepAlivesEnabled(false)
		if err := a.Options.Server.Shutdown(ctx); err != nil {
			a.Options.Logger.Fatalf("Could not gracefully shutdown the server: %v", err)
			os.Exit(pkg.ErrShuttingDownServer)
		}
		close(done)
	}()

	// Start the server
	if err = a.Run(); err != nil {
		a.Options.Logger.Fatalf("Error starting captionthis server: %v", err)
		os.Exit(pkg.ErrStartingServer)
	}

	<-done
}
