package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	jsonFile, err := os.Create("receivedJSONObjects.txt")
	if err != nil {
		panic(err)
	}

	basicHandler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		jsonFile.WriteString("*** RECEIVED PACKET ***\n")
		jsonFile.WriteString(formatRequest(req))
	}

	http.HandleFunc("/DGAHost/serverIP/add", basicHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// formatRequest generates ascii representation of a request
func formatRequest(r *http.Request) string {
	// Create return string
	var request []string // Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)                             // Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host)) // Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		// Just record the content-type header
		if name == "content-type" {
			for _, h := range headers {
				request = append(request, fmt.Sprintf("%v: %v", name, h))
			}
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		fmt.Println("Post request received")
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		request = append(request, buf.String())
		request = append(request, "\n")
	} // Return the request as a string
	return strings.Join(request, "\n")
}
