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

type Server struct {
	port int

	db          database.Service
	OAuthConfig *oauth2.Config
	*echo.Echo
}

func NewServer() *http.Server {
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	NewServer := &Server{
		port: port,

		db: database.NewService(),
	}

	// Declare Server config
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", NewServer.port),
		Handler:      NewServer.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}
