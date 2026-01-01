/*
Package server implements the application's network transport layer.
It initializes the HTTP server, configures timeouts, and manages 
core service dependencies like the database and router.
*/
package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"Glupulse_V0.2/internal/database"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

// Server defines the configuration and dependencies for the HTTP service.
type Server struct {
	// port specifies the TCP port the server will listen on.
	port int

	// db provides access to the database service and connection pool.
	db database.Service

	// OAuthConfig holds the credentials and endpoints for OAuth2 providers.
	OAuthConfig *oauth2.Config

	// Echo is the underlying web framework instance.
	*echo.Echo
}

// NewServer initializes a new Server instance and returns a configured *http.Server.
// It reads configuration from environment variables and sets production-ready 
// network timeouts.
func NewServer() *http.Server {
	// Attempt to parse port from environment; fallback to 8080 if not set or invalid.
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil || port == 0 {
		port = 8080 
	}

	// Initialize the Server struct with its required services.
	newApp := &Server{
		port: port,
		db:   database.NewService(),
	}

	// Configure the standard library http.Server with the application's router and timeouts.
	// 
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", newApp.port),
		Handler:      newApp.RegisterRoutes(), // Injected from routes.go
		IdleTimeout:  time.Minute,             // Time to wait for the next request on keep-alive connections.
		ReadTimeout:  10 * time.Second,        // Maximum duration for reading the entire request.
		WriteTimeout: 30 * time.Second,        // Maximum duration before timing out writes of the response.
	}

	return server
}