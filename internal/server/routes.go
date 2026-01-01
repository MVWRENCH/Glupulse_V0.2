/*
Package server implements the HTTP transport layer for the Glupulse platform.
It manages routing, template rendering, middleware orchestration, and 
centralized error handling for User, Seller, and Admin domains.
*/
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"

	user "Glupulse_V0.2/internal/User"
	"Glupulse_V0.2/internal/admin"
	"Glupulse_V0.2/internal/auth"
	"Glupulse_V0.2/internal/database"
	"Glupulse_V0.2/internal/seller"
	"Glupulse_V0.2/internal/utility"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
)

// TemplateRenderer implements the echo.Renderer interface for HTML template execution.
type TemplateRenderer struct {
	templates *template.Template
}

// Render executes a specific HTML template by name and writes it to the response stream.
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

// RegisterRoutes initializes the Echo router, configures global middlewares, 
// and defines all public and protected API and web endpoints.
func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()

	// --- Global Middleware ---
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"https://*", "http://*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Platform"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// --- Static Assets & Templates ---
	e.Static("/static", "web/public")
	e.Renderer = &TemplateRenderer{
		templates: template.Must(template.ParseGlob("web/templates/*.html")),
	}

	// --- Public Authentication Routes ---
	e.POST("/signup", auth.SignupHandler)
	e.POST("/login", auth.LoginHandler)
	e.POST("/verify-otp", auth.VerifyOTPHandler)
	e.POST("/resend-otp", auth.ResendOTPHandler)
	e.POST("/password/reset/request", auth.RequestPasswordResetHandler)
	e.POST("/password/reset/complete", auth.ResetPasswordHandler)
	e.GET("/auth/verify-email-change", user.VerifyEmailChangeHandler)

	// --- Seller Specific Authentication ---
	e.POST("/auth/seller/signup", auth.SellerSignupHandler)
	e.POST("/auth/seller/verify-otp", auth.VerifySellerOTPHandler)

	// --- Admin Specific Authentication ---
	e.POST("/auth/admin/login", auth.AdminLoginHandler)
	e.POST("/auth/admin/register", auth.AdminRegisterHandler)
	e.POST("/auth/admin/logout", auth.AdminLogoutHandler)
	e.POST("/auth/admin/refresh", auth.AdminRefreshTokenHandler)

	// --- Public Web Pages (Seller/Account Entry) ---
	e.GET("/health", s.healthHandler)
	e.GET("/seller/login", s.renderLoginHandler)
	e.GET("/seller/register", s.renderRegisterHandler)
	e.GET("/seller/verify-otp", s.RenderOTPHandler)
	e.GET("/seller/forgot_password", s.RenderForgotPasswordHandler)

	// --- Public Web Pages (Admin Entry) ---
	e.GET("/admin/login", s.renderAdminLoginHandler)

	// --- OAuth & Identity Federation ---
	e.GET("/auth/:provider", auth.ProviderHandler)
	e.GET("/auth/:provider/callback", auth.SellerWebGoogleAuthCallbackHandler)
	e.POST("/auth/mobile/google", auth.MobileGoogleAuthHandler)
	e.POST("/auth/refresh", auth.RefreshHandler)

	e.Use(LoggerMiddleware)

	// --- PROTECTED USER ROUTES ---
	protected := e.Group("")
	protected.Use(auth.JwtAuthMiddleware)

	// Account & Profile Management
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

	// Address Management
	protected.POST("/addresses", user.CreateAddressHandler)
	protected.GET("/addresses", user.GetAddressesHandler)
	protected.PUT("/addresses/:address_id", user.UpdateAddressHandler)
	protected.DELETE("/addresses/:address_id", user.DeleteAddressHandler)
	protected.POST("/addresses/:address_id/set-default", user.SetDefaultAddressHandler)

	// Commerce (Cart & Orders)
	protected.GET("/cart", user.GetCartHandler)
	protected.POST("/cart/add", user.AddItemToCartHandler)
	protected.PUT("/cart/update", user.UpdateCartItemHandler)
	protected.POST("/cart/remove", user.RemoveItemFromCartHandler)
	protected.POST("/checkout", user.CheckoutHandler)
	protected.GET("/foods", user.ListAllFoodsHandler)
	protected.GET("/foods/:seller_id", user.ListPublicSellerMenuHandler)
	protected.GET("/food/categories", user.ListAllFoodCategoriesHandler)
	protected.GET("/order/history", user.GetUserOrderHistoryHandler)
	protected.GET("/order/active", user.TrackUserActiveOrdersHandler)
	protected.POST("/orders/pay", user.SimulatePaymentHandler)
	protected.POST("/reviews", user.CreateSellerReviewHandler)

	// Clinical Health Data
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

	// AI Orchestration & Feedback
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

	// --- PROTECTED SELLER ROUTES ---
	sellerGroup := e.Group("")
	sellerGroup.Use(auth.JwtAuthMiddleware)
	sellerGroup.Use(auth.SellerActionGuard)

	// Web Dashboard Pages
	sellerGroup.GET("/seller/dashboard", s.RenderSellerDashboardHandler)
	sellerGroup.GET("/seller/orders", s.RenderSellerDashboardHandler)
	sellerGroup.GET("/seller/menu", s.RenderSellerDashboardHandler)
	sellerGroup.GET("/seller/reports", s.RenderSellerDashboardHandler)
	sellerGroup.GET("/seller/store-reviews", s.RenderSellerDashboardHandler)
	sellerGroup.GET("/seller/store-profile", s.RenderSellerDashboardHandler)

	// Real-time Updates & API
	sellerGroup.GET("/seller/ws", seller.DashboardSocketHandler)
	sellerGroup.GET("/seller/menus", seller.ListSellerInventoryHandler)
	sellerGroup.GET("/seller/menu/:food_id", seller.GetFoodDetailHandler)
	sellerGroup.POST("/seller/menu", seller.CreateFoodHandler)
	sellerGroup.PUT("/seller/menu/:food_id", seller.UpdateFoodHandler)
	sellerGroup.DELETE("/seller/menu/:food_id", seller.DeleteFoodHandler)
	sellerGroup.GET("/seller/profile", seller.GetSellerProfileByIDHandler)
	sellerGroup.GET("/seller/profile/:seller_id", seller.GetPublicSellerProfileHandler)
	sellerGroup.PUT("/seller/profile", seller.UpdateSellerProfileHandler)
	sellerGroup.GET("/seller/orders/incoming", seller.GetIncomingOrdersHandler)
	sellerGroup.GET("/seller/orders/active", seller.GetActiveOrdersHandler)
	sellerGroup.GET("/seller/orders/history", seller.GetOrderHistoryHandler)
	sellerGroup.PUT("/seller/orders/status/:order_id", seller.UpdateOrderStatusHandler)
	sellerGroup.GET("/seller/stats", seller.GetSellerDashboardStatsHandler)
	sellerGroup.GET("/seller/stats/chart", seller.GetSellerSalesChartHandler)
	sellerGroup.GET("/seller/reviews", seller.GetSellerReviewsHandler)
	sellerGroup.POST("/seller/reviews/reply/:review_id", seller.ReplyToReviewHandler)

	// --- PROTECTED ADMIN ROUTES ---
	adminGroup := e.Group("/admin")
	adminGroup.Use(auth.AdminJwtAuthMiddleware)

	// System Management Pages
	adminGroup.GET("/dashboard", s.RenderAdminHandler)
	adminGroup.GET("/verifications/seller", s.RenderAdminHandler)
	adminGroup.GET("/verifications/menu", s.RenderAdminHandler)
	adminGroup.GET("/list/users", s.RenderAdminHandler)
	adminGroup.GET("/list/sellers", s.RenderAdminHandler)
	adminGroup.GET("/data/foods", s.RenderAdminHandler)
	adminGroup.GET("/data/ai-analytics", s.RenderAdminHandler)
	adminGroup.GET("/security/logs", s.RenderAdminHandler)
	adminGroup.GET("/system/access", s.RenderAdminHandler)
	adminGroup.GET("/system/health", s.RenderAdminHandler)
	adminGroup.GET("/system/settings", s.RenderAdminHandler)

	// Backend API Endpoints
	adminGroup.GET("/ws", admin.AdminWebSocketHandler)
	adminGroup.GET("/dashboard/stats", admin.GetAdminDashboardHandler)
	adminGroup.PUT("/verify-seller/:seller_id", admin.VerifySellerHandler)
	adminGroup.PUT("/verify-food/:food_id", admin.ApproveFoodHandler)
	adminGroup.GET("/pending-food/:food_id", admin.GetPendingFoodDetailHandler)
	adminGroup.GET("/pending-sellerprofile/:seller_id", admin.GetPendingSellerProfileHandler)
	adminGroup.GET("/pending-seller", admin.GetPendingSellersHandler)
	adminGroup.GET("/pending-food", admin.GetPendingFoodsHandler)
	adminGroup.GET("/users", admin.AdminListUsersHandler)
	adminGroup.GET("/users/:user_id", admin.AdminGetUserOverviewHandler)
	adminGroup.PUT("/users/status/:user_id", admin.AdminUpdateUserStatusHandler)
	adminGroup.PUT("/users/notes/:user_id", admin.AdminUpdateNotesHandler)
	adminGroup.POST("/users/force-reset/:user_id", admin.AdminForceResetHandler)
	adminGroup.GET("/sellers", admin.AdminListSellersHandler)
	adminGroup.GET("/seller/:seller_id", admin.AdminGetSellerDetailHandler)
	adminGroup.PUT("/seller/status/:seller_id", admin.AdminUpdateSellerStatusHandler)
	adminGroup.PUT("/seller/notes/:seller_id", admin.AdminUpdateSellerNotesHandler)
	adminGroup.GET("/seller/reviews/:seller_id", admin.AdminGetSellerReviewsHandler)
	adminGroup.DELETE("/seller/reviews/:review_id", admin.AdminDeleteReviewHandler)
	adminGroup.GET("/seller/menu/:seller_id", admin.AdminGetSellerMenuHandler)
	adminGroup.GET("/foods", admin.AdminListAllFoodsHandler)
	adminGroup.GET("/food/:food_id", admin.AdminGetFoodDetailHandler)
	adminGroup.PUT("/food/visibility/:food_id", admin.AdminToggleFoodActiveHandler)
	adminGroup.DELETE("/food/:food_id", admin.AdminDeleteFoodHandler)
	adminGroup.GET("/ai/dashboard", admin.GetAIAnalyticsDashboardHandler)
	adminGroup.GET("/ai/sessions", admin.AdminListAllSessionsHandler)
	adminGroup.GET("/ai/sessions/:session_id", admin.GetSessionAuditHandler)
	adminGroup.GET("/logs/auth", admin.AdminListAuthLogsHandler)
	adminGroup.GET("/access/admins", admin.ListAdminsHandler)
	adminGroup.POST("/access/admin", admin.CreateAdminHandler)
	adminGroup.PATCH("/access/admin/role/:admin_id", admin.UpdateAdminRoleHandler)
	adminGroup.DELETE("/access/admin/:admin_id", admin.DeleteAdminHandler)
	adminGroup.GET("/server/health", admin.GetServerHealthHandler)
	adminGroup.PATCH("/update/username", admin.UpdateProfileHandler)
	adminGroup.PATCH("/update/password", admin.ChangePasswordHandler)

	return e
}

// healthHandler provides a diagnostic endpoint returning the database connection status.
func (s *Server) healthHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, s.db.Health())
}

// getUserDataFromContext serializes user identity and raw OAuth metadata from the context.
func getUserDataFromContext(c echo.Context) (map[string]interface{}, error) {
	userInterface := c.Get("user")
	if userInterface == nil {
		return nil, fmt.Errorf("user not found in context")
	}

	user, ok := userInterface.(*database.User)
	if !ok {
		return nil, fmt.Errorf("user context has wrong type: %T", userInterface)
	}

	rawGothData := make(map[string]interface{})
	if len(user.UserRawData) > 0 {
		if err := json.Unmarshal(user.UserRawData, &rawGothData); err != nil {
			log.Warn().Msgf("getUserDataFromContext: failed to parse user metadata: %v", err)
		}
	}

	return map[string]interface{}{
		"user":     user,
		"gothData": rawGothData,
	}, nil
}

// LoggerMiddleware generates a unique Request ID for every transaction and injects 
// a scoped zerolog instance into the request context.
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

/* =================================================================================
                          		SELLER VIEW HANDLERS
=================================================================================*/

func (s *Server) renderLoginHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "login.html", nil)
}

func (s *Server) renderRegisterHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "register.html", nil)
}

func (s *Server) RenderOTPHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "otp.html", nil)
}

func (s *Server) RenderForgotPasswordHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "forgot_password.html", nil)
}

// RenderSellerDashboardHandler aggregates merchant identity and profile data for the dashboard UI.
func (s *Server) RenderSellerDashboardHandler(c echo.Context) error {
	ctx := c.Request().Context()

	data, err := getUserDataFromContext(c)
	if err != nil {
		log.Error().Err(err).Msg("Unauthorized access attempt to seller dashboard")
		return c.Redirect(http.StatusTemporaryRedirect, "/seller/login")
	}

	userID, err := utility.GetUserIDFromContext(c)
	if err != nil {
		return c.Redirect(http.StatusTemporaryRedirect, "/seller/login")
	}

	sellerProfile, err := seller.GetSellerProfile(ctx, userID)
	if err != nil {
		log.Info().Msgf("User %s lacks seller profile, redirecting to onboarding", userID)
		return c.Redirect(http.StatusTemporaryRedirect, "/seller/register")
	}

	data["seller"] = sellerProfile
	data["store_name"] = sellerProfile.StoreName
	data["verification_status"] = sellerProfile.VerificationStatus

	return c.Render(http.StatusOK, "index.html", data)
}

/* =================================================================================
                          		ADMIN VIEW HANDLERS
=================================================================================*/

func (s *Server) renderAdminLoginHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "admin_login.html", nil)
}

func (s *Server) RenderAdminHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "admin_index.html", map[string]interface{}{})
}