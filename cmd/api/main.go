package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	user "Glupulse_V0.2/internal/User"
	"Glupulse_V0.2/internal/auth"
	"Glupulse_V0.2/internal/database"
	seller "Glupulse_V0.2/internal/seller"
	"Glupulse_V0.2/internal/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func gracefulShutdown(apiServer *http.Server, done chan bool) {
	// Create context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Listen for the interrupt signal.
	<-ctx.Done()

	log.Info().Msg("shutting down gracefully, press Ctrl+C again to force")
	stop() // Allow Ctrl+C to force shutdown

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Info().Msgf("Server forced to shutdown with error: %v", err)
	}

	log.Info().Msg("Server exiting")

	// Notify the main goroutine that the shutdown is complete
	done <- true
}

func main() {

	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339, // Use a human-readable time format
	})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Info().Msg("Zerolog initialized...")

	dbService := database.NewService()
	defer dbService.Close() // Ensure the database connection is closed on exit.

	if err := auth.InitAuth(database.Dbpool); err != nil {
		log.Fatal().Err(err).Msgf("Fatal error: could not initialize authentication providers: %v", err)
	}

	user.InitUserPackage(database.Dbpool)

	seller.InitSellerPackage(database.Dbpool)

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
	log.Info().Msg("Graceful shutdown complete.")
}
