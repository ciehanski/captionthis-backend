package main

import (
	"log"
	"os"

	"github.com/ciehanski/captionthis-backend/pkg"
)

func main() {
	api, err := pkg.New(pkg.Options{
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
	defer api.CloseDB()

	if err = api.Run(os.Getenv("addr")); err != nil {
		log.Fatal(err)
	}
}
