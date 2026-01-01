package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	user "Glupulse_V0.2/internal/User"
	"Glupulse_V0.2/internal/admin"
	"Glupulse_V0.2/internal/auth"
	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/seller"
	"Glupulse_V0.2/internal/server"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// 1. Initialize Logger
	setupLogger()

	// 2. Initialize Database Connection
	// Using a Service pattern is good; ensure it handles the pool internally.
	dbService := database.NewService()
	defer func() {
		log.Info().Msg("Closing database connection...")
		dbService.Close()
	}()

	// 3. Dependency Injection & Package Initialization
	// We pass the database pool explicitly to ensure packages are testable.
	if err := initSubsystems(database.Dbpool); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize subsystems")
	}

	// 4. Background Workers (Broadcasters)
	// These run in the background to handle real-time updates.
	go admin.StartServerHealthBroadcaster()
	go admin.StartDashboardBroadcaster(database.Dbpool)

	// 5. Server Configuration
	srv := server.NewServer()

	// 6. Graceful Shutdown Orchestration
	// We use a channel to wait for the shutdown process to finish before exiting main.
	idleConnsClosed := make(chan struct{})
	go handleShutdown(srv, idleConnsClosed)

	log.Info().Msgf("Server starting on %s", srv.Addr)

	// 7. Start Server
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Msg("HTTP server failed to start")
	}

	// Wait here until handleShutdown signals completion
	<-idleConnsClosed
	log.Info().Msg("Application stopped successfully.")
}

// setupLogger configures zerolog for better readability during development.
func setupLogger() {
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	})
	// In production, we might want to remove ConsoleWriter for JSON logging.
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Info().Msg("Logging system initialized")
}

// initSubsystems centralizes the setup of different modules.
func initSubsystems(db interface{}) error {
	log.Info().Msg("Initializing application modules...")

	if err := auth.InitAuth(database.Dbpool); err != nil {
		return fmt.Errorf("auth init: %w", err)
	}

	// Initialize individual domain logic
	user.InitUserPackage(database.Dbpool)
	seller.InitSellerPackage(database.Dbpool)
	admin.InitAdminPackage(database.Dbpool)

	return nil
}

// handleShutdown listens for system interrupts and shuts down the server gracefully.
func handleShutdown(srv *http.Server, idleConnsClosed chan struct{}) {
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received
	sig := <-sigint
	log.Info().Msgf("Received signal: %v. Starting graceful shutdown...", sig)

	// Create a deadline for the shutdown process (10 seconds)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("HTTP server Shutdown error")
	}

	// Close the channel to signal main() that we are done
	close(idleConnsClosed)
}
