package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"
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
	protected.GET("user/data", user.GetUserDataAllHandler)

	//User's Addresses Management
	protected.POST("/addresses", user.CreateAddressHandler)
	protected.GET("/addresses", user.GetAddressesHandler)
	protected.PUT("/addresses/:address_id", user.UpdateAddressHandler)
	protected.DELETE("/addresses/:address_id", user.DeleteAddressHandler)
	protected.POST("/addresses/:address_id/set-default", user.SetDefaultAddressHandler)

	//Cart & Order Routes
	protected.GET("/cart", user.GetCartHandler)
	protected.POST("/cart/add", user.AddItemToCartHandler)
	protected.PUT("/cart/update", user.UpdateCartItemHandler)
	protected.POST("/cart/remove", user.RemoveItemFromCartHandler) // Use POST to support a body
	protected.POST("/checkout", user.CheckoutHandler)
	protected.GET("/foods", user.ListAllFoodsHandler)

	//Health Data Routes
	protected.GET("/health/profile", user.GetHealthProfileHandler)
	protected.PUT("/health/profile", user.UpsertHealthProfileHandler)
	protected.POST("/health/hba1c", user.CreateHBA1CRecordHandler)
	protected.GET("/health/hba1c", user.GetHBA1CRecordsHandler)
	protected.PUT("/health/hba1c/:record_id", user.UpdateHBA1CRecordHandler)
	protected.DELETE("/health/hba1c/:record_id", user.DeleteHBA1CRecordHandler)
	protected.POST("/health/events", user.CreateHealthEventHandler)
	protected.GET("/health/events", user.GetHealthEventsHandler)
	protected.PUT("/health/events/:event_id", user.UpdateHealthEventHandler)
	protected.DELETE("/health/events/:event_id", user.DeleteHealthEventHandler)
	protected.POST("/health/glucose", user.CreateGlucoseReadingHandler)
	protected.GET("/health/glucose", user.GetGlucoseReadingsHandler)
	protected.PUT("/health/glucose/:reading_id", user.UpdateGlucoseReadingHandler)
	protected.DELETE("/health/glucose/:reading_id", user.DeleteGlucoseReadingHandler)
	protected.GET("/health/activity_type", user.GetActivityTypesHandler)
	protected.POST("/health/log/activity", user.CreateActivityLogHandler)
	protected.GET("/health/log/activity", user.GetActivityLogsHandler)
	protected.PUT("/health/log/activity/:activity_id", user.UpdateActivityLogHandler)
	protected.DELETE("/health/log/activity/:activity_id", user.DeleteActivityLogHandler)
	protected.POST("/health/log/sleep", user.CreateSleepLogHandler)
	protected.GET("/health/log/sleep", user.GetSleepLogsHandler)
	protected.PUT("/health/log/sleep/:sleep_id", user.UpdateSleepLogHandler)
	protected.DELETE("/health/log/sleep/:sleep_id", user.DeleteSleepLogHandler)
	protected.POST("/health/medication", user.CreateUserMedicationHandler)
	protected.GET("/health/medication", user.GetUserMedicationsHandler)
	protected.PUT("/health/medication/:medication_id", user.UpdateUserMedicationHandler)
	protected.DELETE("/health/medication/:medication_id", user.DeleteUserMedicationHandler)
	protected.POST("/health/log/medication", user.CreateMedicationLogHandler)
	protected.GET("/health/log/medication", user.GetMedicationLogsHandler)
	protected.PUT("/health/log/medication/:medicationlog_id", user.UpdateMedicationLogHandler)
	protected.DELETE("/health/log/medication/:medicationlog_id", user.DeleteMedicationLogHandler)
	protected.POST("/health/log/meal", user.CreateMealLogHandler)
	protected.GET("/health/log/meals", user.GetAllMealLogsHandler)
	protected.GET("/health/log/meal/:meallog_id", user.GetMealLogHandler)
	protected.PUT("/health/log/meal/:meallog_id", user.UpdateMealLogHandler)
	protected.DELETE("/health/log/meal/:meallog_id", user.DeleteMealLogHandler)

	//Recommendations
	protected.POST("/recommendations", user.GetRecommendationsHandler)
	protected.GET("/recommendations", user.GetRecommendationSessionsHandler)
	protected.GET("/recommendation/:session_id", user.GetRecommendationSessionDetailHandler)

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
