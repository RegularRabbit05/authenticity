package main

import (
	"authenticity/server"
	"authenticity/types"
	"fmt"
	"log"
	"net/http"
	"os"

	gorillaHandler "github.com/gorilla/handlers"
)

func main() {
	var application types.App
	err := application.AppLoadConfig()
	if err != nil {
		log.Fatalln("Failed to load configuration:", err)
	}

	if _, err = os.Stat("com.html"); os.IsNotExist(err) {
		log.Println("No communication handler file found (com.html)")
	} else {
		comHandler, err := os.ReadFile("com.html")
		if err != nil {
			log.Fatalln("Failed to read com.html:", err)
		}
		http.HandleFunc("/authenticity/_comHandler", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write(comHandler)
		})
	}

	http.HandleFunc("/authenticity/_registerSession", server.AuthenticationHandler(&application))
	http.HandleFunc("/", server.ProxyConnectionHandler(&application))

	log.Printf("Starting server on port %d...\n", application.Port)
	err = http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", application.Port), gorillaHandler.ProxyHeaders(gorillaHandler.LoggingHandler(os.Stdout, gorillaHandler.RecoveryHandler()(http.DefaultServeMux))))
	if err != nil {
		log.Fatalln("Failed to start server:", err)
	}
}
