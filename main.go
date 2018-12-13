package main

import (
	"log"
	"os"

	"github.com/ciehanski/captionthis-backend/api"
)

func main() {
	a, err := api.New(api.Options{
		Version: "v1beta",
		DBhost:  os.Getenv("dbhost"),
		DBname:  os.Getenv("dbname"),
		DBuser:  os.Getenv("dbuser"),
		DBpass:  os.Getenv("dbpass"),
		DBssl:   os.Getenv("dbssl"),
		Debug:   true,
	})
	if err != nil {
		log.Fatal(err)
	}
	// Gracefully close connection to database
	defer func() {
		if err := a.CloseDB(); err != nil {
			log.Fatal(err)
		}
	}()

	if err = a.Run(os.Getenv("addr")); err != nil {
		log.Fatal(err)
	}
}
