package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"Glupulse_V0.2/internal/auth"
	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/server"
)

func gracefulShutdown(apiServer *http.Server, done chan bool) {
	// Create context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Listen for the interrupt signal.
	<-ctx.Done()

	log.Println("shutting down gracefully, press Ctrl+C again to force")
	stop() // Allow Ctrl+C to force shutdown

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown with error: %v", err)
	}

	log.Println("Server exiting")

	// Notify the main goroutine that the shutdown is complete
	done <- true
}

func main() {
	// FIX: Initialize the database connection first.
	// This call runs the code in NewService(), which populates the exported 'database.Dbpool' variable.
	dbService := database.NewService()
	defer dbService.Close() // Ensure the database connection is closed on exit.

	// FIX: Now that database.Dbpool is initialized and exported, this call will work.
	if err := auth.InitAuth(database.Dbpool); err != nil {
		log.Fatalf("Fatal error: could not initialize authentication providers: %v", err)
	}

	// It's likely your NewServer will need the database service, so you would pass it here.
	// Example: server := server.NewServer(dbService)
	server := server.NewServer()

	// Create a done channel to signal when the shutdown is complete
	done := make(chan bool, 1)

	// Run graceful shutdown in a separate goroutine
	go gracefulShutdown(server, done)

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		panic(fmt.Sprintf("http server error: %s", err))
	}

	// Wait for the graceful shutdown to complete
	<-done
	log.Println("Graceful shutdown complete.")
}
