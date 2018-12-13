package api

import (
	"log"
	"net"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

// Faster JSON parsing
// ref: https://github.com/json-iterator/go
var json = jsoniter.ConfigCompatibleWithStandardLibrary

// jsonResponse builds a map containing the response's status and error message
func jsonResponse(status int, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}

// respond takes any interface and spits it out in JSON format
// with the necessary headers
func respond(w http.ResponseWriter, data interface{}) {
	// Set Headers
	w.Header().Set("Accept-Charset", "utf-8")
	w.Header().Add("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Access-Control-Allow-Origin", "localhost")

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Panic(err)
	}
}

// getRemoteIP retrieves the remote IP address of the requesting HTTP-client.
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
