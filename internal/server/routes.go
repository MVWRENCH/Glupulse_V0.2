package server

import (
	"encoding/json"
	"io"
	"net/http"
	"text/template"

	"fmt"
	"log"
	"time"

	"Glupulse_V0.2/internal/auth"
	"Glupulse_V0.2/internal/database"
	"github.com/coder/websocket"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// TemplateRenderer is a custom html/template renderer for Echo framework
type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	// Use ExecuteTemplate to select the correct template by name
	return t.templates.ExecuteTemplate(w, name, data)
}

func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"https://*", "http://*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Platform"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	renderer := &TemplateRenderer{
		// FIX: Include login.html and register.html in glob pattern if they are in web/
		templates: template.Must(template.ParseGlob("web/*.html")),
	}
	e.Renderer = renderer

	// --- Public Auth Routes (Traditional) ---
	e.POST("/signup", auth.SignupHandler) // New route for traditional registration (mobile/web API)
	e.POST("/login", auth.LoginHandler)   // POST route for traditional login (mobile/web API)
	e.POST("/verify-otp", auth.VerifyOTPHandler)
	e.POST("/resend-otp", auth.ResendOTPHandler)

	// Public routes (Web pages)
	e.GET("/health", s.healthHandler)
	e.GET("/websocket", s.websocketHandler)
	e.GET("/login", s.renderLoginHandler)       // Serves the login.html page
	e.GET("/register", s.renderRegisterHandler) // Serves the register.html page
	e.GET("/verify", s.OTPHandler)              // Serves the otp.html page

	// Web OAuth routes
	e.GET("/auth/:provider", auth.ProviderHandler)
	e.GET("/auth/:provider/callback", auth.CallbackHandler)

	// Mobile auth route - Android/iOS Google Sign-In
	e.POST("/auth/mobile/google", auth.MobileGoogleAuthHandler)

	// Refresh token endpoint (both web and mobile)
	e.POST("/auth/refresh", auth.RefreshHandler)

	// Protected routes
	protected := e.Group("")
	protected.Use(auth.JwtAuthMiddleware)

	// Split protected welcome routes
	protected.GET("/welcome/web", s.welcomeWebHandler)       // Web client landing page
	protected.GET("/welcome/mobile", s.welcomeMobileHandler) // Mobile client JSON response

	protected.GET("/logout", auth.LogoutHandler)

	return e
}

func (s *Server) healthHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, s.db.Health())
}

func (s *Server) websocketHandler(c echo.Context) error {
	w := c.Response().Writer
	r := c.Request()
	socket, err := websocket.Accept(w, r, nil)

	if err != nil {
		log.Printf("could not open websocket: %v", err)
		_, _ = w.Write([]byte("could not open websocket"))
		w.WriteHeader(http.StatusInternalServerError)
		return nil
	}

	defer socket.Close(websocket.StatusGoingAway, "server closing websocket")

	ctx := r.Context()
	socketCtx := socket.CloseRead(ctx)

	for {
		payload := fmt.Sprintf("server timestamp: %d", time.Now().UnixNano())
		err := socket.Write(socketCtx, websocket.MessageText, []byte(payload))
		if err != nil {
			break
		}
		time.Sleep(time.Second * 2)
	}
	return nil
}

// renderLoginHandler serves the public login.html page.
func (s *Server) renderLoginHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "index.html", nil)
}

// renderRegisterHandler serves the public register.html page.
func (s *Server) renderRegisterHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "register.html", nil)
}

func (s *Server) OTPHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "otp.html", nil)
}

// getUserDataFromContext extracts and combines user and Goth raw data from the context.
func getUserDataFromContext(c echo.Context) (map[string]interface{}, error) {
	// The type from the context is *database.User
	user, ok := c.Get("user").(*database.User)
	if !ok {
		return nil, fmt.Errorf("could not get user from context")
	}

	// Create a map to hold the unmarshalled raw JSON data from OAuth
	var rawGothData map[string]interface{}

	// Check if raw data exists and try to unmarshal it
	if user.UserRawData != nil {
		if err := json.Unmarshal(user.UserRawData, &rawGothData); err != nil {
			log.Printf("welcomeHandler: could not unmarshal raw user data: %v", err)
			// Continue even if unmarshalling fails
		}
	}

	// Create a combined response map to send all relevant data.
	response := map[string]interface{}{
		"user":     user,
		"gothData": rawGothData,
	}

	return response, nil
}

// welcomeWebHandler handles the web client landing page (renders HTML).
func (s *Server) welcomeWebHandler(c echo.Context) error {
	data, err := getUserDataFromContext(c)
	if err != nil {
		log.Println("welcomeWebHandler:", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/login")
	}

	// Render welcome.html template
	return c.Render(http.StatusOK, "welcome.html", data)
}

// welcomeMobileHandler handles the mobile client JSON response.
func (s *Server) welcomeMobileHandler(c echo.Context) error {
	data, err := getUserDataFromContext(c)
	if err != nil {
		log.Println("welcomeMobileHandler:", err)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized or session expired"})
	}

	// Return the combined data as JSON for the mobile client
	return c.JSON(http.StatusOK, data)
}
