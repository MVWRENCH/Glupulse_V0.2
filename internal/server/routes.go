package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"

	user "Glupulse_V0.2/internal/User"
	"Glupulse_V0.2/internal/auth"
	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/seller"
	"Glupulse_V0.2/internal/utility"
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

	e.Static("/static", "web/public")

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("web/templates/*.html")),
	}
	e.Renderer = renderer

	// Traditional Auth Routes
	e.POST("/signup", auth.SignupHandler)
	e.POST("/auth/seller/signup", auth.SellerSignupHandler)
	e.POST("/login", auth.LoginHandler)
	e.POST("/verify-otp", auth.VerifyOTPHandler)
	e.POST("/auth/seller/verify-otp", auth.VerifySellerOTPHandler)
	e.POST("/resend-otp", auth.ResendOTPHandler)
	e.POST("/password/reset/request", auth.RequestPasswordResetHandler)
	e.POST("/password/reset/complete", auth.ResetPasswordHandler)
	e.GET("/auth/verify-email-change", user.VerifyEmailChangeHandler)

	// Seller Web pages routes
	e.GET("/health", s.healthHandler)
	e.GET("/seller/login", s.renderLoginHandler)                    // Serves the login.html page
	e.GET("/seller/register", s.renderRegisterHandler)              // Serves the register.html page
	e.GET("/seller/verify-otp", s.RenderOTPHandler)                 // Serves the otp.html page
	e.GET("/seller/forgot_password", s.RenderForgotPasswordHandler) // Serves the forgot_password.html page

	// Seller Web OAuth routes
	e.GET("/auth/:provider", auth.ProviderHandler)
	e.GET("/auth/:provider/callback", auth.SellerWebGoogleAuthCallbackHandler)

	// Mobile auth route - Android/iOS Google Sign-In
	e.POST("/auth/mobile/google", auth.MobileGoogleAuthHandler)

	// Refresh token endpoint (both web and mobile)
	e.POST("/auth/refresh", auth.RefreshHandler)

	e.Use(LoggerMiddleware)

	// Protected routes
	protected := e.Group("")
	protected.Use(auth.JwtAuthMiddleware)

	// User's Account & Profile Functions Routes
	protected.GET("/profile", user.GetUserProfileHandler)
	protected.PUT("/profile", user.UpdateUserProfileHandler)
	protected.PUT("/profile/password", user.UpdatePasswordHandler)
	protected.POST("/profile/update-email", user.RequestEmailChangeHandler)
	protected.PUT("/profile/username", user.UpdateUsernameHandler)
	protected.DELETE("/profile", user.DeleteAccountHandler)
	protected.POST("/auth/mobile/google/link", auth.LinkGoogleAccountHandler)
	protected.POST("/auth/mobile/google/unlink", auth.UnlinkGoogleAccountHandler)
	protected.GET("user/data", user.GetUserDataAllHandler)
	protected.GET("/logout", auth.LogoutHandler)

	//User's Addresses Management Functions Routes
	protected.POST("/addresses", user.CreateAddressHandler)
	protected.GET("/addresses", user.GetAddressesHandler)
	protected.PUT("/addresses/:address_id", user.UpdateAddressHandler)
	protected.DELETE("/addresses/:address_id", user.DeleteAddressHandler)
	protected.POST("/addresses/:address_id/set-default", user.SetDefaultAddressHandler)

	//User Cart & Order Functions Routes
	protected.GET("/cart", user.GetCartHandler)
	protected.POST("/cart/add", user.AddItemToCartHandler)
	protected.PUT("/cart/update", user.UpdateCartItemHandler)
	protected.POST("/cart/remove", user.RemoveItemFromCartHandler) // Use POST to support a body
	protected.POST("/checkout", user.CheckoutHandler)
	protected.GET("/foods", user.ListAllFoodsHandler)
	protected.GET("/food/categories", user.ListAllFoodCategoriesHandler)
	protected.GET("/order/history", user.GetUserOrderHistoryHandler)
	protected.GET("/order/active", user.TrackUserActiveOrdersHandler)
	protected.POST("/orders/pay", user.SimulatePaymentHandler)
	protected.POST("/reviews", user.CreateSellerReviewHandler)

	//User Health Data Function Routes
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

	//User Recommendations Functions Routes
	protected.POST("/recommendations", user.GetRecommendationsHandler)
	protected.GET("/recommendations", user.GetRecommendationSessionsHandler)
	protected.GET("/recommendation/:session_id", user.GetRecommendationSessionDetailHandler)
	protected.POST("/recommendation/feedback/:session_id", user.SubmitSessionFeedbackHandler)
	protected.POST("/recommendation/feedback/food/:session_id", user.SubmitFoodFeedbackHandler)
	protected.POST("/recommendation/feedback/food/view/:session_id", user.MarkFoodViewedHandler)
	protected.POST("/recommendation/feedback/food/purchased/:session_id", user.MarkFoodPurchasedHandler)
	protected.POST("/recommendation/feedback/food/addtocart/:session_id", user.MarkFoodAddedToCartHandler)
	protected.POST("/recommendation/feedback/activity/:session_id", user.SubmitActivityFeedbackHandler)
	protected.POST("/recommendation/feedback/activity/view/:session_id", user.MarkActivityViewedHandler)
	protected.POST("/recommendation/feedback/activity/completed/:session_id", user.MarkActivityCompletedHandler)

	//Seller Protected Web Page
	protected.GET("/seller/dashboard", s.RenderSellerDashboardHandler)
	protected.GET("/seller/orders", s.RenderSellerDashboardHandler)
	protected.GET("/seller/menu", s.RenderSellerDashboardHandler)
	protected.GET("/seller/reports", s.RenderSellerDashboardHandler)
	protected.GET("/seller/store-reviews", s.RenderSellerDashboardHandler)
	protected.GET("/seller/store-profile", s.RenderSellerDashboardHandler)

	//Websocket for seller dashboard website client
	protected.GET("/seller/ws", seller.DashboardSocketHandler)

	//Seller Functions Routes
	protected.GET("seller/menus", seller.ListSellerFoodsHandler)
	protected.GET("seller/menu/:food_id", seller.GetFoodDetailHandler)
	protected.POST("seller/menu", seller.CreateFoodHandler)
	protected.PUT("seller/menu/:food_id", seller.UpdateFoodHandler)
	protected.DELETE("seller/menu/:food_id", seller.DeleteFoodHandler)
	protected.GET("/seller/profile", seller.GetSellerProfileByIDHandler)
	protected.GET("/seller/profile/:seller_id", seller.GetPublicSellerProfileHandler)
	protected.GET("/seller/orders/incoming", seller.GetIncomingOrdersHandler)
	protected.GET("/seller/orders/active", seller.GetActiveOrdersHandler)
	protected.GET("/seller/orders/history", seller.GetOrderHistoryHandler)
	protected.PUT("/seller/orders/status/:order_id", seller.UpdateOrderStatusHandler)
	protected.GET("/seller/stats", seller.GetSellerDashboardStatsHandler)
	protected.GET("/seller/stats/chart", seller.GetSellerSalesChartHandler)
	protected.PUT("/seller/profile", seller.UpdateSellerProfileHandler)
	protected.GET("/seller/reviews", seller.GetSellerReviewsHandler)
	protected.POST("/seller/reviews/reply/:review_id", seller.ReplyToReviewHandler)

	return e
}

func (s *Server) healthHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, s.db.Health())
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

/* ====================================================================
                   		Seller Web Handler
==================================================================== */

// renderLoginHandler serves the public login.html page.
func (s *Server) renderLoginHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "login.html", nil)
}

// renderRegisterHandler serves the public register.html page.
func (s *Server) renderRegisterHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "register.html", nil)
}

func (s *Server) RenderOTPHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "otp.html", nil)
}

func (s *Server) RenderForgotPasswordHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "forgot_password.html", nil)
}

// RenderSellerDashboardHandler renders the seller dashboard
func (s *Server) RenderSellerDashboardHandler(c echo.Context) error {
	ctx := c.Request().Context()

	// 1. Get Base User Data (from Token/Context)
	// This usually returns map[string]interface{} with user details
	data, err := getUserDataFromContext(c)
	if err != nil {
		log.Error().Err(err).Msg("RenderSellerDashboardHandler: User data not found")
		return c.Redirect(http.StatusTemporaryRedirect, "/seller/login")
	}

	// 2. Extract User ID to fetch Seller Profile
	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.Redirect(http.StatusTemporaryRedirect, "/seller/login")
	}

	// 3. Fetch Seller Profile from DB
	sellerProfile, err := seller.GetSellerProfile(ctx, userID)
	if err != nil {
		// CASE: User is logged in but has NO seller profile yet.
		log.Info().Msgf("User %s tried to access dashboard but has no shop", userID)
		return c.Redirect(http.StatusTemporaryRedirect, "/seller/register")
	}

	// 4. Inject Seller Data into the Template Payload
	data["seller"] = sellerProfile
	data["store_name"] = sellerProfile.StoreName
	data["verification_status"] = sellerProfile.VerificationStatus

	// 5. Render
	return c.Render(http.StatusOK, "index.html", data)
}
