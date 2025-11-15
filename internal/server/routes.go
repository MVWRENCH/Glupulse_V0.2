package server

import (
	"encoding/json"
	"io"
	"net/http"
	"text/template"

	"fmt"
	//"log"
	"time"

	user "Glupulse_V0.2/internal/User"
	"Glupulse_V0.2/internal/auth"
	"Glupulse_V0.2/internal/database"
	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
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
		templates: template.Must(template.ParseGlob("web/*.html")),
	}
	e.Renderer = renderer

	// --- Public Auth Routes (Traditional) ---
	e.POST("/signup", auth.SignupHandler) // New route for traditional registration (mobile/web API)
	e.POST("/login", auth.LoginHandler)   // POST route for traditional login (mobile/web API)
	e.POST("/verify-otp", auth.VerifyOTPHandler)
	e.POST("/resend-otp", auth.ResendOTPHandler)
	e.POST("/password/reset/request", auth.RequestPasswordResetHandler)
	e.POST("/password/reset/complete", auth.ResetPasswordHandler)

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

	e.GET("/auth/verify-email-change", user.VerifyEmailChangeHandler)

	e.Use(LoggerMiddleware)

	// Protected routes
	protected := e.Group("")
	protected.Use(auth.JwtAuthMiddleware)

	// Split protected welcome routes
	protected.GET("/welcome/web", s.welcomeWebHandler)
	protected.GET("/welcome/mobile", s.welcomeMobileHandler)
	protected.GET("/logout", auth.LogoutHandler)

	// User's functions Routes
	protected.GET("/profile", user.GetUserProfileHandler)
	protected.PUT("/profile", user.UpdateUserProfileHandler)
	protected.PUT("/profile/password", user.UpdatePasswordHandler)
	protected.POST("/profile/update-email", user.RequestEmailChangeHandler)
	protected.PUT("/profile/username", user.UpdateUsernameHandler)
	protected.DELETE("/profile", user.DeleteAccountHandler)
	protected.POST("/auth/mobile/google/link", auth.LinkGoogleAccountHandler)
	protected.POST("/auth/mobile/google/unlink", auth.UnlinkGoogleAccountHandler)
	protected.GET("/recommendations", user.GetRecommendationHandler)

	//User's Addresses Management
	protected.POST("/addresses", user.CreateAddressHandler)
	protected.GET("/addresses", user.GetAddressesHandler)
	protected.PUT("/addresses/:address_id", user.UpdateAddressHandler)
	protected.DELETE("/addresses/:address_id", user.DeleteAddressHandler)
	protected.POST("/addresses/:address_id/set-default", user.SetDefaultAddressHandler)

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
		log.Info().Msgf("could not open websocket: %v", err)
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
	// Try to get user from context
	userInterface := c.Get("user")
	if userInterface == nil {
		return nil, fmt.Errorf("user not found in context")
	}

	user, ok := userInterface.(*database.User)
	if !ok {
		return nil, fmt.Errorf("user context has wrong type: %T", userInterface)
	}

	// Create a map to hold the unmarshalled raw JSON data from OAuth
	var rawGothData map[string]interface{}

	// Check if raw data exists and try to unmarshal it
	if len(user.UserRawData) > 0 {
		if err := json.Unmarshal(user.UserRawData, &rawGothData); err != nil {
			log.Info().Msgf("getUserDataFromContext: could not unmarshal raw user data: %v", err)
			// Continue even if unmarshalling fails - set empty map
			rawGothData = make(map[string]interface{})
		}
	} else {
		// No raw data (traditional user) - set empty map
		rawGothData = make(map[string]interface{})
	}

	// Create a combined response map to send all relevant data
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
		log.Error().Err(err).Msg("welcomeWebHandler")
		return c.Redirect(http.StatusTemporaryRedirect, "/login")
	}

	// Render welcome.html template
	return c.Render(http.StatusOK, "welcome.html", data)
}

// welcomeMobileHandler handles the mobile client JSON response.
func (s *Server) welcomeMobileHandler(c echo.Context) error {
	data, err := getUserDataFromContext(c)
	if err != nil {
		log.Error().Err(err).Msg("welcomeWebHandler")
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized or session expired"})
	}

	// Return the combined data as JSON for the mobile client
	return c.JSON(http.StatusOK, data)
}

func LoggerMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		requestID := c.Request().Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Response().Header().Set("X-Request-ID", requestID)

		logger := log.With().Str("request_id", requestID).Logger()

		c.Set("logger", &logger)

		return next(c)
	}
}
