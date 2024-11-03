package main

import (
	"log"
	"voting-backend/api"
)

func main() {
	server := api.NewServer()
	log.Println("Starting voting system API on :8080...")
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
