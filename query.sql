/* ====================================================================
                     Authentication Queries
==================================================================== */
-- Traditional Auth Users
-- name: CreateUser :one
INSERT INTO users (
    user_id,
    user_username,
    user_password,
    user_firstname,
    user_lastname,
    user_email,
    user_dob,
    user_gender,
    user_accounttype,
    created_at,
    is_email_verified,
    email_verified_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
) RETURNING *;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE user_username = $1;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE user_email = $1;

-- name: GetUserByID :one
SELECT * FROM users
WHERE user_id = $1;

-- name: UpdateUserLastLogin :exec
UPDATE users
SET user_last_login_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateUserProfile :one
UPDATE users
SET 
    user_firstname = COALESCE($2, user_firstname),
    user_lastname = COALESCE($3, user_lastname),
    user_email = COALESCE($4, user_email),
    user_dob = COALESCE($5, user_dob),
    user_gender = COALESCE($6, user_gender)
WHERE user_id = $1
RETURNING *;

-- name: CheckUsernameExists :one
SELECT EXISTS(
    SELECT 1 FROM users WHERE user_username = $1
) AS exists;

-- name: CheckEmailExists :one
SELECT EXISTS(
    SELECT 1 FROM users WHERE user_email = $1
) AS exists;

-- OAuth Integration - Upsert user with OAuth data
-- name: UpsertOAuthUser :one
INSERT INTO users (
    user_id,
    user_email,
    user_name_auth,
    user_avatar_url,
    user_provider,
    user_provider_user_id,
    user_raw_data,
    user_last_login_at,
    user_email_auth,
    user_username,
    user_password
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
ON CONFLICT (user_provider, user_provider_user_id) 
DO UPDATE SET 
    -- Update fields based on EXCLUDED (the row that was attempted to be inserted)
    user_email = COALESCE(EXCLUDED.user_email, users.user_email),
    user_name_auth = EXCLUDED.user_name_auth,
    user_avatar_url = EXCLUDED.user_avatar_url,
    user_raw_data = EXCLUDED.user_raw_data,
    user_last_login_at = EXCLUDED.user_last_login_at
RETURNING *;

-- name: UpdateUserGoogleLink :exec
UPDATE users
SET 
  user_name_auth = $1,
  user_avatar_url = $2,
  user_provider = $3,
  user_provider_user_id = $4,
  user_raw_data = $5,
  user_email_auth = $6
WHERE 
  user_id = $7;

-- name: UnlinkGoogleAccount :exec
UPDATE users
SET 
  user_name_auth = NULL,
  user_provider = NULL,
  user_provider_user_id = NULL,
  user_avatar_url = NULL,   -- Clear the avatar linked to Google
  user_raw_data = NULL     -- Clear the raw data from Google
WHERE 
  user_id = $1;

-- name: GetUserByOAuthEmail :one
SELECT * FROM users
WHERE user_email_auth = $1 AND user_provider IS NOT NULL;

-- Refresh Tokens (renamed table)
-- name: CreateRefreshToken :one
INSERT INTO users_refresh_tokens (
    user_id,
    token_hash,
    device_info,
    ip_address,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM users_refresh_tokens
WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: RevokeRefreshToken :exec
UPDATE users_refresh_tokens 
SET revoked_at = CURRENT_TIMESTAMP
WHERE id = $1;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE users_refresh_tokens 
SET revoked_at = CURRENT_TIMESTAMP
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: CreateAuthLog :one
INSERT INTO logs_auth (
    user_id,
    log_category,
    log_action,
    log_message,
    log_level,
    ip_address,
    user_agent,
    metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING *;

-- name: UpdateUserPassword :exec
UPDATE users
SET user_password = $2
WHERE user_id = $1;

-- name: CreateEmailChangeRequest :one
INSERT INTO user_email_change_requests (
    user_id,
    new_email,
    verification_token,
    expires_at
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: GetEmailChangeRequestByToken :one
SELECT *
FROM user_email_change_requests
WHERE
    verification_token = $1;

-- name: DeleteEmailChangeRequest :exec
DELETE FROM user_email_change_requests
WHERE
    request_id = $1;

-- name: UpdateUserEmail :exec
UPDATE users
SET user_email = $2
WHERE user_id = $1;

-- name: UpdateUserUsername :exec
UPDATE users
SET user_username = $2
WHERE user_id = $1;

-- name: DeleteUser :exec
DELETE FROM users
WHERE user_id = $1;

-- name: VerifyUserEmail :exec
UPDATE users
SET is_email_verified = $2,
    email_verified_at = $3
WHERE user_id = $1;

-- name: GetUserProviderID :one
SELECT * FROM users
WHERE user_provider_user_id = $1 LIMIT 1;

-- name: CreatePendingRegistration :one
INSERT INTO pending_registrations
    (entity_role, email, username, hashed_password, first_name, last_name, raw_data, expires_at)
VALUES
    ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING pending_id; -- Return the new pending_id

-- name: GetPendingRegistrationByEmail :one
SELECT * FROM pending_registrations
WHERE email = $1 AND expires_at > NOW();

-- name: GetPendingRegistrationByUsername :one
SELECT * FROM pending_registrations
WHERE username = $1 AND expires_at > NOW();

-- name: GetPendingRegistrationByID :one
SELECT * FROM pending_registrations
WHERE pending_id = $1 AND expires_at > NOW();

-- name: DeletePendingRegistration :exec
DELETE FROM pending_registrations
WHERE pending_id = $1;

-- name: DeleteExpiredPendingRegistrations :exec
DELETE FROM pending_registrations
WHERE expires_at < NOW();

-- name: CreateOTPCode :one
INSERT INTO otp_codes (
    entity_id,
    entity_role,
    otp_secret,
    otp_purpose,
    otp_attempts,
    expires_at,
    deletion_scheduled_at
) VALUES (
    $1, $2, $3, $4, 0, $5, $6
)
RETURNING *;

-- name: GetOTPCodeByEntityID :one
-- Don't check expires_at here, we'll handle expiry in code
SELECT * FROM otp_codes
WHERE entity_id = $1
ORDER BY created_at DESC
LIMIT 1;

-- name: UpdateOTPAttempts :exec
UPDATE otp_codes
SET otp_attempts = otp_attempts + 1
WHERE otp_id = $1;

-- name: DeleteOTPCode :exec
DELETE FROM otp_codes
WHERE otp_id = $1;

-- name: DeleteOTPCodeByEntityID :exec
DELETE FROM otp_codes
WHERE entity_id = $1;

-- name: DeleteScheduledOTPCodes :exec
-- Delete OTPs that are scheduled for deletion and time has passed
DELETE FROM otp_codes
WHERE deletion_scheduled_at IS NOT NULL 
AND deletion_scheduled_at <= NOW();

-- name: CountActiveOTPCodes :one
-- Count OTPs that haven't expired yet
SELECT COUNT(*) FROM otp_codes
WHERE expires_at > NOW();

-- name: GetOTPCodeWithCooldown :one
SELECT * FROM otp_codes
WHERE entity_id = $1
AND created_at > NOW() - INTERVAL '1 minute'
ORDER BY created_at DESC
LIMIT 1;

-- name: CleanupExpiredRefreshTokens :exec
DELETE FROM users_refresh_tokens
WHERE expires_at < NOW() - INTERVAL '7 days';

-- name: CleanupRevokedRefreshTokens :exec
DELETE FROM users_refresh_tokens
WHERE revoked_at < NOW() - INTERVAL '30 days';

/* ====================================================================
                   Addresses Management Queries
==================================================================== */

-- name: CreateUserAddress :one
INSERT INTO user_addresses (
    user_id,
    address_line1,
    address_line2,
    address_district,
    address_city,
    address_province,
    address_postalcode,
    address_latitude,
    address_longitude,
    address_label,
    recipient_name,
    recipient_phone,
    delivery_notes,
    is_default
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
) RETURNING *;

-- name: GetUserAddresses :many
SELECT * FROM user_addresses
WHERE user_id = $1 AND is_active = true
ORDER BY is_default DESC, created_at DESC;

-- name: GetUserAddressByID :one
SELECT * FROM user_addresses
WHERE address_id = $1 AND user_id = $2 AND is_active = true;

-- name: GetDefaultAddress :one
SELECT * FROM user_addresses
WHERE user_id = $1 AND is_default = true AND is_active = true
LIMIT 1;

-- name: UpdateUserAddress :one
UPDATE user_addresses
SET 
    address_line1 = COALESCE(sqlc.narg('address_line1'), address_line1),
    address_line2 = COALESCE(sqlc.narg('address_line2'), address_line2),
    address_district = COALESCE(sqlc.narg('address_district'), address_district),
    address_city = COALESCE(sqlc.narg('address_city'), address_city),
    address_province = COALESCE(sqlc.narg('address_province'), address_province),
    address_postalcode = COALESCE(sqlc.narg('address_postalcode'), address_postalcode),
    address_latitude = COALESCE(sqlc.narg('address_latitude'), address_latitude),
    address_longitude = COALESCE(sqlc.narg('address_longitude'), address_longitude),
    address_label = COALESCE(sqlc.narg('address_label'), address_label),
    recipient_name = COALESCE(sqlc.narg('recipient_name'), recipient_name),
    recipient_phone = COALESCE(sqlc.narg('recipient_phone'), recipient_phone),
    delivery_notes = COALESCE(sqlc.narg('delivery_notes'), delivery_notes)
WHERE address_id = $1 AND user_id = $2 AND is_active = true
RETURNING *;

-- name: SetDefaultAddress :one
UPDATE user_addresses
SET is_default = true
WHERE address_id = $1 AND user_id = $2 AND is_active = true
RETURNING *;

-- name: UnsetDefaultAddress :exec
UPDATE user_addresses
SET is_default = false
WHERE user_id = $1 AND address_id != $2 AND is_default = true;

-- name: DeleteUserAddress :exec
UPDATE user_addresses
SET is_active = false, is_default = false
WHERE address_id = $1 AND user_id = $2;

-- name: HardDeleteUserAddress :exec
DELETE FROM user_addresses
WHERE address_id = $1 AND user_id = $2;

-- name: CountUserAddresses :one
SELECT COUNT(*) FROM user_addresses
WHERE user_id = $1 AND is_active = true;

-- name: CheckAddressOwnership :one
SELECT EXISTS(
    SELECT 1 FROM user_addresses
    WHERE address_id = $1 AND user_id = $2 AND is_active = true
);

-- name: IfAddressIsDefault :one
SELECT is_default FROM user_addresses
WHERE address_id = $1;

/* ====================================================================
                   Cart & Order Management Queries
==================================================================== */

-- name: GetCartByUserID :one
SELECT * FROM user_carts
WHERE user_id = $1;

-- name: CreateCart :one
INSERT INTO user_carts (user_id)
VALUES ($1)
RETURNING *;

-- name: GetCartItems :many
SELECT 
    ci.*,
    f.food_name,
    f.price,
    f.photo_url,
    f.seller_id
FROM user_cart_items ci
JOIN foods f ON ci.food_id = f.food_id
WHERE ci.cart_id = $1;

-- name: UpsertCartItem :one
-- Adds an item to the cart, or increases its quantity if it already exists
INSERT INTO user_cart_items (
    cart_id,
    food_id,
    quantity
) VALUES (
    $1, $2, $3
)
ON CONFLICT (cart_id, food_id)
DO UPDATE SET
    quantity = user_cart_items.quantity + $3
RETURNING *;

-- name: UpdateCartItemQuantity :one
UPDATE user_cart_items
SET quantity = $3
WHERE cart_id = $1 AND food_id = $2
RETURNING *;

-- name: DeleteCartItem :exec
DELETE FROM user_cart_items
WHERE cart_id = $1 AND food_id = $2;

-- name: ClearCart :exec
-- Deletes all items from a cart
DELETE FROM user_cart_items
WHERE cart_id = $1;

-- name: SetCartSeller :exec
UPDATE user_carts
SET seller_id = $2
WHERE user_id = $1;

-- name: ClearCartSeller :exec
-- This is called when the last item is removed from a cart
UPDATE user_carts
SET seller_id = NULL
WHERE cart_id = $1;

-- name: GetFoodForUpdate :one
-- Locks the food row to check stock during a transaction
SELECT food_id, food_name, price, stock_count, is_available FROM foods
WHERE food_id = $1
FOR UPDATE;

-- name: CreateOrder :one
INSERT INTO user_orders (
    user_id,
    seller_id,
    total_price,
    status,
    delivery_address_json,
    payment_status,
    payment_method
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
RETURNING *;

-- name: CreateOrderItem :one
INSERT INTO user_order_items (
    order_id,
    food_id,
    quantity,
    price_at_purchase,
    food_name_snapshot
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: GetUserOrders :many
SELECT * FROM user_orders
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: GetOrderDetails :one
-- Secure: checks that the order_id also belongs to the user_id
SELECT * FROM user_orders
WHERE order_id = $1 AND user_id = $2;

-- name: GetOrderItems :many
SELECT * FROM user_order_items
WHERE order_id = $1;

-- name: GetFood :one
SELECT * FROM foods
WHERE food_id = $1;

-- name: AssignUserRole :exec
INSERT INTO user_roles (user_id, role_id)
SELECT $1, role_id FROM roles WHERE role_name = $2;

-- name: GetSellerProfile :one
SELECT * FROM seller_profiles
WHERE seller_id = $1;

-- name: ListAllAvailableFoods :many
-- Retrieves a list of all food items currently marked as available
SELECT *
FROM foods
WHERE is_available = true
ORDER BY food_name;


/* ====================================================================
                   Health Profile Queries
==================================================================== */

-- name: GetUserHealthProfile :one
SELECT * FROM user_health_profiles
WHERE user_id = $1 LIMIT 1;

-- name: UpsertUserHealthProfile :one
INSERT INTO user_health_profiles (
    user_id,
    app_experience,
    condition_id,
    diagnosis_date,
    years_with_condition,
    treatment_types,
    target_glucose_fasting,
    target_glucose_postprandial,
    uses_cgm,
    cgm_device,
    cgm_api_connected,
    height_cm,
    current_weight_kg,
    target_weight_kg,
    waist_circumference_cm,
    body_fat_percentage,
    hba1c_target,
    last_hba1c,
    last_hba1c_date,
    activity_level,
    daily_steps_goal,
    weekly_exercise_goal_minutes,
    preferred_activity_type_ids,
    dietary_pattern,
    daily_carb_target_grams,
    daily_calorie_target,
    daily_protein_target_grams,
    daily_fat_target_grams,
    meals_per_day,
    snacks_per_day,
    food_allergies,
    food_intolerances,
    foods_to_avoid,
    cultural_cuisines,
    dietary_restrictions,
    has_hypertension,
    hypertension_medication,
    has_kidney_disease,
    kidney_disease_stage,
    egfr_value,
    has_cardiovascular_disease,
    has_neuropathy,
    has_retinopathy,
    has_gastroparesis,
    has_hypoglycemia_unawareness,
    other_conditions,
    smoking_status,
    smoking_years,
    alcohol_frequency,
    alcohol_drinks_per_week,
    stress_level,
    typical_sleep_hours,
    sleep_quality,
    is_pregnant,
    is_breastfeeding,
    expected_due_date,
    preferred_units,
    glucose_unit,
    timezone,
    language_code,
    enable_glucose_alerts,
    enable_meal_reminders,
    enable_activity_reminders,
    enable_medication_reminders,
    share_data_for_research,
    share_anonymized_data
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $60, $61, $62, $63, $64, $65, $66
)
ON CONFLICT (user_id) DO UPDATE SET
    app_experience = COALESCE($2, user_health_profiles.app_experience),
    condition_id = COALESCE($3, user_health_profiles.condition_id),
    diagnosis_date = COALESCE($4, user_health_profiles.diagnosis_date),
    years_with_condition = COALESCE($5, user_health_profiles.years_with_condition),
    treatment_types = COALESCE($6, user_health_profiles.treatment_types),
    target_glucose_fasting = COALESCE($7, user_health_profiles.target_glucose_fasting),
    target_glucose_postprandial = COALESCE($8, user_health_profiles.target_glucose_postprandial),
    uses_cgm = COALESCE($9, user_health_profiles.uses_cgm),
    cgm_device = COALESCE($10, user_health_profiles.cgm_device),
    cgm_api_connected = COALESCE($11, user_health_profiles.cgm_api_connected),
    height_cm = COALESCE($12, user_health_profiles.height_cm),
    current_weight_kg = COALESCE($13, user_health_profiles.current_weight_kg),
    target_weight_kg = COALESCE($14, user_health_profiles.target_weight_kg),
    waist_circumference_cm = COALESCE($15, user_health_profiles.waist_circumference_cm),
    body_fat_percentage = COALESCE($16, user_health_profiles.body_fat_percentage),
    hba1c_target = COALESCE($17, user_health_profiles.hba1c_target),
    last_hba1c = COALESCE($18, user_health_profiles.last_hba1c),
    last_hba1c_date = COALESCE($19, user_health_profiles.last_hba1c_date),
    activity_level = COALESCE($20, user_health_profiles.activity_level),
    daily_steps_goal = COALESCE($21, user_health_profiles.daily_steps_goal),
    weekly_exercise_goal_minutes = COALESCE($22, user_health_profiles.weekly_exercise_goal_minutes),
    preferred_activity_type_ids = COALESCE($23, user_health_profiles.preferred_activity_type_ids),
    dietary_pattern = COALESCE($24, user_health_profiles.dietary_pattern),
    daily_carb_target_grams = COALESCE($25, user_health_profiles.daily_carb_target_grams),
    daily_calorie_target = COALESCE($26, user_health_profiles.daily_calorie_target),
    daily_protein_target_grams = COALESCE($27, user_health_profiles.daily_protein_target_grams),
    daily_fat_target_grams = COALESCE($28, user_health_profiles.daily_fat_target_grams),
    meals_per_day = COALESCE($29, user_health_profiles.meals_per_day),
    snacks_per_day = COALESCE($30, user_health_profiles.snacks_per_day),
    food_allergies = COALESCE($31, user_health_profiles.food_allergies),
    food_intolerances = COALESCE($32, user_health_profiles.food_intolerances),
    foods_to_avoid = COALESCE($33, user_health_profiles.foods_to_avoid),
    cultural_cuisines = COALESCE($34, user_health_profiles.cultural_cuisines),
    dietary_restrictions = COALESCE($35, user_health_profiles.dietary_restrictions),
    has_hypertension = COALESCE($36, user_health_profiles.has_hypertension),
    hypertension_medication = COALESCE($37, user_health_profiles.hypertension_medication),
    has_kidney_disease = COALESCE($38, user_health_profiles.has_kidney_disease),
    kidney_disease_stage = COALESCE($39, user_health_profiles.kidney_disease_stage),
    egfr_value = COALESCE($40, user_health_profiles.egfr_value),
    has_cardiovascular_disease = COALESCE($41, user_health_profiles.has_cardiovascular_disease),
    has_neuropathy = COALESCE($42, user_health_profiles.has_neuropathy),
    has_retinopathy = COALESCE($43, user_health_profiles.has_retinopathy),
    has_gastroparesis = COALESCE($44, user_health_profiles.has_gastroparesis),
    has_hypoglycemia_unawareness = COALESCE($45, user_health_profiles.has_hypoglycemia_unawareness),
    other_conditions = COALESCE($46, user_health_profiles.other_conditions),
    smoking_status = COALESCE($47, user_health_profiles.smoking_status),
    smoking_years = COALESCE($48, user_health_profiles.smoking_years),
    alcohol_frequency = COALESCE($49, user_health_profiles.alcohol_frequency),
    alcohol_drinks_per_week = COALESCE($50, user_health_profiles.alcohol_drinks_per_week),
    stress_level = COALESCE($51, user_health_profiles.stress_level),
    typical_sleep_hours = COALESCE($52, user_health_profiles.typical_sleep_hours),
    sleep_quality = COALESCE($53, user_health_profiles.sleep_quality),
    is_pregnant = COALESCE($54, user_health_profiles.is_pregnant),
    is_breastfeeding = COALESCE($55, user_health_profiles.is_breastfeeding),
    expected_due_date = COALESCE($56, user_health_profiles.expected_due_date),
    preferred_units = COALESCE($57, user_health_profiles.preferred_units),
    glucose_unit = COALESCE($58, user_health_profiles.glucose_unit),
    timezone = COALESCE($59, user_health_profiles.timezone),
    language_code = COALESCE($60, user_health_profiles.language_code),
    enable_glucose_alerts = COALESCE($61, user_health_profiles.enable_glucose_alerts),
    enable_meal_reminders = COALESCE($62, user_health_profiles.enable_meal_reminders),
    enable_activity_reminders = COALESCE($63, user_health_profiles.enable_activity_reminders),
    enable_medication_reminders = COALESCE($64, user_health_profiles.enable_medication_reminders),
    share_data_for_research = COALESCE($65, user_health_profiles.share_data_for_research),
    share_anonymized_data = COALESCE($66, user_health_profiles.share_anonymized_data)
RETURNING *;

-- name: DeleteUserHealthProfile :exec
DELETE FROM user_health_profiles
WHERE user_id = $1;

-- name: CreateHBA1CRecord :one
INSERT INTO user_hba1c_records (
    user_id,
    test_date,
    hba1c_percentage,
    hba1c_mmol_mol,
    estimated_avg_glucose,
    treatment_changed,
    medication_changes,
    diet_changes,
    activity_changes,
    change_from_previous,
    trend,
    notes,
    document_url
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
)
RETURNING *;

-- name: GetHBA1CRecords :many
-- Retrieves all records for the user, ordered newest first
SELECT * FROM user_hba1c_records
WHERE user_id = $1
ORDER BY test_date DESC, created_at DESC;

-- name: GetHBA1CRecordByID :one
-- Retrieves a single record, checking for user ownership
SELECT * FROM user_hba1c_records
WHERE hba1c_id = $1 AND user_id = $2;

-- name: UpdateHBA1CRecord :one
-- Updates an existing record, checking for user ownership
UPDATE user_hba1c_records
SET
    test_date = COALESCE($3, test_date),
    hba1c_percentage = COALESCE($4, hba1c_percentage),
    hba1c_mmol_mol = COALESCE($5, hba1c_mmol_mol),
    estimated_avg_glucose = COALESCE($6, estimated_avg_glucose),
    treatment_changed = COALESCE($7, treatment_changed),
    medication_changes = COALESCE($8, medication_changes),
    diet_changes = COALESCE($9, diet_changes),
    activity_changes = COALESCE($10, activity_changes),
    notes = COALESCE($11, notes),
    document_url = COALESCE($12, document_url),
    trend = COALESCE($13, trend) -- Trend will be calculated on the client/server
WHERE 
    hba1c_id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteHBA1CRecord :exec
-- Deletes a record, checking for user ownership
DELETE FROM user_hba1c_records
WHERE hba1c_id = $1 AND user_id = $2;

-- name: GetLastHBA1CRecord :one
-- Retrieves the most recent record to compare against for trend analysis
SELECT hba1c_percentage FROM user_hba1c_records
WHERE user_id = $1 
  AND test_date < $2 -- CRITICAL: Only look at records older than the current one
ORDER BY test_date DESC, created_at DESC
LIMIT 1;

-- name: CreateHealthEvent :one
INSERT INTO user_health_events (
    user_id,
    event_date,
    event_type,
    severity,
    glucose_value,
    ketone_value_mmol,
    symptoms,
    treatments,
    required_medical_attention,
    notes
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING *;

-- name: GetHealthEvents :many
-- Retrieves all health events for the user, ordered newest first
SELECT * FROM user_health_events
WHERE user_id = $1
ORDER BY event_date DESC, created_at DESC;

-- name: GetHealthEventByID :one
-- Retrieves a single event, checking for user ownership
SELECT * FROM user_health_events
WHERE event_id = $1 AND user_id = $2;

-- name: UpdateHealthEvent :one
-- Updates an existing record, checking for user ownership
UPDATE user_health_events
SET
    event_date = COALESCE($3, event_date),
    event_type = COALESCE($4, event_type),
    severity = COALESCE($5, severity),
    glucose_value = COALESCE($6, glucose_value),
    ketone_value_mmol = COALESCE($7, ketone_value_mmol),
    symptoms = COALESCE($8, symptoms),
    treatments = COALESCE($9, treatments),
    required_medical_attention = COALESCE($10, required_medical_attention),
    notes = COALESCE($11, notes)
WHERE 
    event_id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteHealthEvent :exec
-- Deletes a record, checking for user ownership
DELETE FROM user_health_events
WHERE event_id = $1 AND user_id = $2;

-- name: CreateGlucoseReading :one
INSERT INTO user_glucose_readings (
    user_id,
    glucose_value,
    reading_timestamp,
    reading_type,
    source,
    device_id,
    device_name,
    is_flagged,
    flag_reason,
    is_outlier,
    notes,
    symptoms
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
RETURNING *;

-- name: GetGlucoseReadings :many
-- Retrieves all readings for the user, ordered newest first, with optional date range
SELECT * FROM user_glucose_readings
WHERE user_id = $1 
  AND reading_timestamp >= COALESCE(sqlc.narg('start_date'), '1900-01-01'::timestamptz)
  AND reading_timestamp <= COALESCE(sqlc.narg('end_date'), NOW() + INTERVAL '1 day')
ORDER BY reading_timestamp DESC;

-- name: GetGlucoseReadingByID :one
-- Retrieves a single reading, checking for user ownership
SELECT * FROM user_glucose_readings
WHERE reading_id = $1 AND user_id = $2;

-- name: UpdateGlucoseReading :one
-- Updates an existing reading, checking for user ownership
UPDATE user_glucose_readings
SET
    glucose_value = COALESCE($3, glucose_value),
    reading_timestamp = COALESCE($4, reading_timestamp),
    reading_type = COALESCE($5, reading_type),
    source = COALESCE($6, source),
    device_id = COALESCE($7, device_id),
    device_name = COALESCE($8, device_name),
    is_flagged = COALESCE($9, is_flagged),
    flag_reason = COALESCE($10, flag_reason),
    is_outlier = COALESCE($11, is_outlier),
    notes = COALESCE($12, notes),
    symptoms = COALESCE($13, symptoms)
WHERE 
    reading_id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteGlucoseReading :exec
-- Deletes a reading, checking for user ownership
DELETE FROM user_glucose_readings
WHERE reading_id = $1 AND user_id = $2;

-- name: GetGlucoseStats :one
-- Retrieves the mean and standard deviation of glucose readings 
-- over the last 7 days for outlier analysis.
SELECT 
    AVG(glucose_value) AS mean_glucose,
    STDDEV(glucose_value) AS stddev_glucose
FROM user_glucose_readings
WHERE user_id = $1 
  AND reading_timestamp >= NOW() - INTERVAL '7 days';

-- name: CreateActivityLog :one
-- Creates a new activity log entry
INSERT INTO user_activity_logs (
    user_id,
    activity_timestamp,
    activity_code,
    intensity,
    perceived_exertion,
    duration_minutes,
    steps_count,
    pre_activity_carbs,
    water_intake_ml,
    issue_description,
    source,
    sync_id,
    notes
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
)
RETURNING *;

-- name: GetActivityLogs :many
-- Retrieves all activity logs for the user, ordered newest first, with optional date range
SELECT * FROM user_activity_logs
WHERE user_id = $1
  AND activity_timestamp >= COALESCE(sqlc.narg('start_date'), '1900-01-01'::timestamptz)
  AND activity_timestamp <= COALESCE(sqlc.narg('end_date'), NOW() + INTERVAL '1 day')
ORDER BY activity_timestamp DESC;

-- name: GetActivityLogByID :one
-- Retrieves a single activity log, checking for user ownership
SELECT * FROM user_activity_logs
WHERE activity_id = $1 AND user_id = $2;

-- name: UpdateActivityLog :one
-- Updates an existing activity log, checking for user ownership
UPDATE user_activity_logs
SET
    activity_timestamp = COALESCE(sqlc.narg('activity_timestamp'), activity_timestamp),
    activity_code = COALESCE(sqlc.narg('activity_code'), activity_code),
    intensity = COALESCE(sqlc.narg('intensity'), intensity),
    perceived_exertion = COALESCE(sqlc.narg('perceived_exertion'), perceived_exertion),
    duration_minutes = COALESCE(sqlc.narg('duration_minutes'), duration_minutes),
    steps_count = COALESCE(sqlc.narg('steps_count'), steps_count),
    pre_activity_carbs = COALESCE(sqlc.narg('pre_activity_carbs'), pre_activity_carbs),
    water_intake_ml = COALESCE(sqlc.narg('water_intake_ml'), water_intake_ml),
    issue_description = COALESCE(sqlc.narg('issue_description'), issue_description),
    source = COALESCE(sqlc.narg('source'), source),
    sync_id = COALESCE(sqlc.narg('sync_id'), sync_id),
    notes = COALESCE(sqlc.narg('notes'), notes)
WHERE 
    activity_id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteActivityLog :exec
-- Deletes an activity log, checking for user ownership
DELETE FROM user_activity_logs
WHERE activity_id = $1 AND user_id = $2;

-- name: CreateSleepLog :one
-- Creates a new sleep log entry
INSERT INTO user_sleep_logs (
    user_id,
    sleep_date,
    bed_time,
    wake_time,
    quality_rating,
    tracker_score,
    deep_sleep_minutes,
    rem_sleep_minutes,
    light_sleep_minutes,
    awake_minutes,
    average_hrv,
    resting_heart_rate,
    tags,
    source,
    notes
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
)
RETURNING *;

-- name: GetSleepLogs :many
-- Retrieves all sleep logs for the user, with date filtering
SELECT * FROM user_sleep_logs
WHERE user_id = $1
  AND bed_time >= COALESCE(sqlc.narg('start_date'), '1900-01-01'::timestamptz)
  AND bed_time <= COALESCE(sqlc.narg('end_date'), NOW() + INTERVAL '1 day')
ORDER BY sleep_date DESC;

-- name: GetSleepLogByID :one
-- Retrieves a single sleep log, checking for user ownership
SELECT * FROM user_sleep_logs
WHERE sleep_id = $1 AND user_id = $2;

-- name: UpdateSleepLog :one
-- Updates an existing sleep log, checking for user ownership
UPDATE user_sleep_logs
SET
    sleep_date = COALESCE(sqlc.narg('sleep_date'), sleep_date),
    bed_time = COALESCE(sqlc.narg('bed_time'), bed_time),
    wake_time = COALESCE(sqlc.narg('wake_time'), wake_time),
    quality_rating = COALESCE(sqlc.narg('quality_rating'), quality_rating),
    tracker_score = COALESCE(sqlc.narg('tracker_score'), tracker_score),
    deep_sleep_minutes = COALESCE(sqlc.narg('deep_sleep_minutes'), deep_sleep_minutes),
    rem_sleep_minutes = COALESCE(sqlc.narg('rem_sleep_minutes'), rem_sleep_minutes),
    light_sleep_minutes = COALESCE(sqlc.narg('light_sleep_minutes'), light_sleep_minutes),
    awake_minutes = COALESCE(sqlc.narg('awake_minutes'), awake_minutes),
    average_hrv = COALESCE(sqlc.narg('average_hrv'), average_hrv),
    resting_heart_rate = COALESCE(sqlc.narg('resting_heart_rate'), resting_heart_rate),
    tags = COALESCE(sqlc.narg('tags'), tags),
    source = COALESCE(sqlc.narg('source'), source),
    notes = COALESCE(sqlc.narg('notes'), notes)
WHERE 
    sleep_id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteSleepLog :exec
-- Deletes a sleep log, checking for user ownership
DELETE FROM user_sleep_logs
WHERE sleep_id = $1 AND user_id = $2;

-- name: CreateUserMedication :one
-- Registers a new medication configuration for the user.
INSERT INTO user_medications (
    user_id,
    display_name,
    medication_type,
    default_dose_unit
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: GetUserMedications :many
-- Retrieves all active medications configured by the user.
SELECT * FROM user_medications
WHERE user_id = $1 AND is_active = true
ORDER BY display_name;

-- name: GetUserMedicationByID :one
-- Retrieves a single medication configuration, checking for user ownership.
SELECT * FROM user_medications
WHERE medication_id = $1 AND user_id = $2;

-- name: UpdateUserMedication :one
-- Updates the configuration of an existing medication.
UPDATE user_medications
SET
    display_name = COALESCE(sqlc.narg('display_name'), display_name),
    medication_type = COALESCE(sqlc.narg('medication_type'), medication_type),
    default_dose_unit = COALESCE(sqlc.narg('default_dose_unit'), default_dose_unit),
    is_active = COALESCE(sqlc.narg('is_active'), is_active)
WHERE
    medication_id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteUserMedication :exec
-- Soft deletes the medication configuration (sets is_active = false).
UPDATE user_medications
SET is_active = false
WHERE medication_id = $1 AND user_id = $2;

-- name: CreateMedicationLog :one
-- Logs a dose taken by the user.
INSERT INTO user_medication_logs (
    user_id,
    medication_id,
    medication_name,
    "timestamp",
    dose_amount,
    reason,
    is_pump_delivery,
    delivery_duration_minutes,
    notes
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING *;

-- name: GetMedicationLogs :many
-- Retrieves logs for the user, with date filtering.
SELECT * FROM user_medication_logs
WHERE user_id = $1
  AND "timestamp" >= COALESCE(sqlc.narg('start_date'), '1900-01-01'::timestamptz)
  AND "timestamp" <= COALESCE(sqlc.narg('end_date'), NOW() + INTERVAL '1 day')
ORDER BY "timestamp" DESC;

-- name: UpdateMedicationLog :one
-- Updates a single logged dose.
UPDATE user_medication_logs
SET
    medication_id = COALESCE(sqlc.narg('medication_id'), medication_id),
    medication_name = COALESCE(sqlc.narg('medication_name'), medication_name),
    "timestamp" = COALESCE(sqlc.narg('timestamp'), "timestamp"),
    dose_amount = COALESCE(sqlc.narg('dose_amount'), dose_amount),
    reason = COALESCE(sqlc.narg('reason'), reason),
    is_pump_delivery = COALESCE(sqlc.narg('is_pump_delivery'), is_pump_delivery),
    delivery_duration_minutes = COALESCE(sqlc.narg('delivery_duration_minutes'), delivery_duration_minutes),
    notes = COALESCE(sqlc.narg('notes'), notes)
WHERE
    medicationlog_id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteMedicationLog :exec
-- Deletes a single dose log.
DELETE FROM user_medication_logs
WHERE medicationlog_id = $1 AND user_id = $2;

-- name: GetActivityTypes :many
-- Retrieves all activity types, ordered by display name
SELECT * FROM activity_types
ORDER BY display_name;

-- name: CreateMealLog :one
INSERT INTO user_meal_logs (
    user_id,
    meal_timestamp,
    meal_type_id,
    description,
    total_calories,
    total_carbs_grams,
    total_protein_grams,
    total_fat_grams,
    total_fiber_grams,
    total_sugar_grams,
    tags
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
RETURNING *;

-- name: UpdateMealLog :one
UPDATE user_meal_logs
SET
    meal_timestamp = COALESCE(sqlc.narg('meal_timestamp'), meal_timestamp),
    meal_type_id = COALESCE(sqlc.narg('meal_type_id'), meal_type_id),
    description = COALESCE(sqlc.narg('description'), description),
    total_calories = COALESCE(sqlc.narg('total_calories'), total_calories),
    total_carbs_grams = COALESCE(sqlc.narg('total_carbs_grams'), total_carbs_grams),
    total_protein_grams = COALESCE(sqlc.narg('total_protein_grams'), total_protein_grams),
    total_fat_grams = COALESCE(sqlc.narg('total_fat_grams'), total_fat_grams),
    total_fiber_grams = COALESCE(sqlc.narg('total_fiber_grams'), total_fiber_grams),
    total_sugar_grams = COALESCE(sqlc.narg('total_sugar_grams'), total_sugar_grams),
    tags = COALESCE(sqlc.narg('tags'), tags)
WHERE 
    meal_id = $1 AND user_id = $2
RETURNING *;

-- name: GetMealLogByID :one
SELECT * FROM user_meal_logs WHERE meal_id = $1 AND user_id = $2;

-- name: GetMealLogs :many
-- Retrieves all meal logs for the user, ordered newest first, with optional date range
SELECT 
    ml.meal_id, 
    ml.meal_timestamp, 
    ml.meal_type_id,
    mt.display_name as meal_type_name,
    ml.description,
    ml.total_calories,
    ml.total_carbs_grams,
    ml.total_protein_grams,
    ml.total_fat_grams,
    ml.total_fiber_grams,
    ml.total_sugar_grams,
    ml.tags,
    ml.created_at,
    ml.updated_at
FROM user_meal_logs ml
JOIN meal_types mt ON ml.meal_type_id = mt.meal_type_id
WHERE user_id = $1
  AND meal_timestamp >= COALESCE(sqlc.narg('start_date'), '1900-01-01'::timestamptz)
  AND meal_timestamp <= COALESCE(sqlc.narg('end_date'), NOW() + INTERVAL '1 day')
ORDER BY meal_timestamp DESC;

-- name: DeleteMealLog :exec
DELETE FROM user_meal_logs
WHERE meal_id = $1 AND user_id = $2;

-- name: CreateMealItem :one
INSERT INTO user_meal_items (
    meal_id,
    food_name,
    food_id,
    seller,
    serving_size,
    serving_size_grams,
    quantity,
    calories,
    carbs_grams,
    fiber_grams,
    protein_grams,
    fat_grams,
    sugar_grams,
    sodium_mg,
    glycemic_index,
    glycemic_load,
    food_category,
    saturated_fat_grams,
    monounsaturated_fat_grams,
    polyunsaturated_fat_grams,
    cholesterol_mg
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
)
RETURNING *;

-- name: DeleteMealItemsByMealID :exec
DELETE FROM user_meal_items WHERE meal_id = $1;

-- name: GetMealItemsByMealID :many
SELECT * FROM user_meal_items
WHERE meal_id = $1
ORDER BY created_at ASC;

/* ====================================================================
                     AI Recommendation Queries
==================================================================== */

-- name: CreateRecommendationSession :exec
--Inserts a new recommendation session after AI generates recommendations. Called in storeRecommendationSession func in recommendation.go
INSERT INTO recommendation_sessions (
    session_id,
    user_id,
    requested_types,
    meal_type,
    food_category_codes,
    food_preferences,
    activity_type_codes,
    activity_preferences,
    insights_question,
    analysis_summary,
    insights_response,
    latest_glucose_value,
    latest_hba1c,
    user_condition_id,
    ai_model_used,
    ai_confidence_score
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
);

-- name: CreateRecommendedFood :exec
-- After AI picks foods, this stores each recommendation with reasoning. Called in processFoodRecommendations func in recommendation.go
INSERT INTO recommended_foods (
    recommendation_food_id,
    session_id,
    food_id,
    reason,
    nutrition_highlight,
    suggested_meal_type,
    suggested_portion_size,
    recommendation_rank,
    confidence_score
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
);

-- name: CreateRecommendedActivity :exec
-- After AI picks activities, this stores each recommendation with reasoning. Called in processActivityRecommendations func in recommendation.go
INSERT INTO recommended_activities (
    recommendation_activity_id,
    session_id,
    activity_id,
    reason,
    recommended_duration_minutes,
    recommended_intensity,
    safety_notes,
    best_time_of_day,
    glucose_management_tip,
    recommendation_rank,
    confidence_score
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
);

-- name: ListRecommendedFoods :many
-- Fetches foods from database based on user's filters BEFORE sending to AI. 
/*
Filters applied:

is_available = true → Only show foods in stock
food_category IN [...] → Only requested categories (e.g., "ASIAN_GENERIC")
glycemic_load <= max → Safety limit (e.g., GL < 10 for diabetics)
carbs_grams <= max → Carb limit (e.g., < 30g per meal)

Ordering:

Primary: Low glycemic load first (safer for blood sugar)
Secondary: High fiber (better for glucose control)
*/
SELECT * FROM foods
WHERE is_available = true
    AND (
        sqlc.narg('food_category')::TEXT[] IS NULL 
        OR food_category::TEXT[] && sqlc.narg('food_category')::TEXT[]
    )
    AND (
        sqlc.narg('max_glycemic_load')::NUMERIC IS NULL 
        OR glycemic_load <= sqlc.narg('max_glycemic_load')
    )
    AND (
        sqlc.narg('max_carbs')::NUMERIC IS NULL 
        OR carbs_grams <= sqlc.narg('max_carbs')
    )
ORDER BY 
    CASE 
        WHEN glycemic_load IS NOT NULL THEN glycemic_load
        ELSE 999
    END ASC,
    fiber_grams DESC,
    protein_grams DESC
LIMIT sqlc.arg(limit_count)::INTEGER;

-- name: ListRecommendedActivities :many
SELECT 
    a.id,
    a.activity_code,
    a.activity_name,
    a.description,
    a.image_url,
    a.met_value,
    a.measurement_unit,
    a.recommended_min_value
FROM activities a
WHERE (
    sqlc.arg(activity_codes)::TEXT[] IS NULL
    OR a.activity_code = ANY(sqlc.arg(activity_codes)::TEXT[])
)
ORDER BY a.met_value ASC
LIMIT 20;

-- name: GetRecommendationSession :one
SELECT * FROM recommendation_sessions
WHERE session_id = $1;

-- name: GetRecommendedFoodsInSession :many
SELECT 
    rf.*,
    f.food_name,
    f.seller_id,
    f.description,
    f.price,
    f.currency,
    f.photo_url,
    f.thumbnail_url,
    f.is_available,
    f.tags,
    f.serving_size,
    f.calories,
    f.carbs_grams,
    f.fiber_grams,
    f.protein_grams,
    f.fat_grams,
    f.sugar_grams,
    f.sodium_mg,
    f.glycemic_index,
    f.glycemic_load
FROM recommended_foods rf
JOIN foods f ON rf.food_id = f.food_id
WHERE rf.session_id = $1
ORDER BY rf.recommendation_rank ASC;

-- name: GetRecommendedActivitiesInSession :many
SELECT 
    ra.*,
    a.activity_code,
    a.activity_name,
    a.description,
    a.image_url,
    a.met_value,
    a.measurement_unit
FROM recommended_activities ra
JOIN activities a ON ra.activity_id = a.id
WHERE ra.session_id = $1
ORDER BY ra.recommendation_rank ASC;

-- name: GetUserRecommendationHistory :many
SELECT 
    rs.session_id,
    rs.created_at,
    rs.analysis_summary,
    rs.meal_type,
    rs.requested_types,
    rs.overall_feedback,
    COUNT(DISTINCT rf.food_id) as foods_count,
    COUNT(DISTINCT ra.activity_id) as activities_count
FROM recommendation_sessions rs
LEFT JOIN recommended_foods rf ON rs.session_id = rf.session_id
LEFT JOIN recommended_activities ra ON rs.session_id = ra.session_id
WHERE rs.user_id = $1
GROUP BY rs.session_id
ORDER BY rs.created_at DESC
LIMIT sqlc.arg(limit_count)::INTEGER;

-- name: MarkFoodAddedToCart :exec
UPDATE recommended_foods
SET was_added_to_cart = true,
    last_interaction_at = NOW()
WHERE session_id = $1 AND food_id = $2;

-- name: MarkFoodPurchased :exec
UPDATE recommended_foods
SET was_purchased = true,
    last_interaction_at = NOW()
WHERE session_id = $1 AND food_id = $2;

-- name: MarkActivityCompleted :exec
UPDATE recommended_activities
SET was_completed = true,
    completed_at = NOW(),
    actual_duration_minutes = $3,
    last_interaction_at = NOW()
WHERE session_id = $1 AND activity_id = $2;

-- name: AddFoodFeedback :exec
UPDATE recommended_foods
SET user_rating = $3,
    feedback = $4,
    feedback_notes = $5,
    glucose_spike_after_eating = $6
WHERE session_id = $1 AND food_id = $2;

-- name: AddActivityFeedback :exec
UPDATE recommended_activities
SET user_rating = $3,
    feedback = $4,
    feedback_notes = $5,
    glucose_change_after_activity = $6
WHERE session_id = $1 AND activity_id = $2;

-- name: AddSessionFeedback :exec
UPDATE recommendation_sessions
SET overall_feedback = $2,
    feedback_notes = $3
WHERE session_id = $1;

-- name: GetLatestGlucoseReading :one
SELECT * FROM user_glucose_readings
WHERE user_id = $1
ORDER BY reading_timestamp DESC
LIMIT 1;

-- name: GetLatestHBA1CRecord :one
SELECT * FROM user_hba1c_records
WHERE user_id = $1
ORDER BY test_date DESC
LIMIT 1;

-- name: GetRecommendationEffectiveness :many
SELECT * FROM recommendation_effectiveness
WHERE user_id = $1
    AND recommendation_date >= sqlc.arg(start_date)::DATE
ORDER BY recommendation_date DESC;

-- name: GetTopRatedFoods :many
SELECT 
    f.food_id,
    f.food_name,
    f.photo_url,
    COUNT(rf.recommendation_food_id) as times_recommended,
    AVG(rf.user_rating) as avg_rating,
    COUNT(rf.recommendation_food_id) FILTER (WHERE rf.was_purchased = true) as purchase_count
FROM foods f
JOIN recommended_foods rf ON f.food_id = rf.food_id
JOIN recommendation_sessions rs ON rf.session_id = rs.session_id
WHERE rs.user_id = $1
    AND rf.user_rating IS NOT NULL
GROUP BY f.food_id
HAVING COUNT(rf.user_rating) >= 3
ORDER BY AVG(rf.user_rating) DESC, COUNT(rf.was_purchased) DESC
LIMIT 10;

-- name: GetTopRatedActivities :many
SELECT 
    a.id,
    a.activity_name,
    a.image_url,
    COUNT(ra.recommendation_activity_id) as times_recommended,
    AVG(ra.user_rating) as avg_rating,
    COUNT(ra.recommendation_activity_id) FILTER (WHERE ra.was_completed = true) as completion_count
FROM activities a
JOIN recommended_activities ra ON a.id = ra.activity_id
JOIN recommendation_sessions rs ON ra.session_id = rs.session_id
WHERE rs.user_id = $1
    AND ra.user_rating IS NOT NULL
GROUP BY a.id
HAVING COUNT(ra.user_rating) >= 3
ORDER BY AVG(ra.user_rating) DESC, COUNT(ra.was_completed) DESC
LIMIT 10;


-- name: GetUserDemographics :one
SELECT 
    CAST(EXTRACT(YEAR FROM AGE(CURRENT_DATE, user_DOB)) AS INTEGER) as age,
    user_gender
FROM users
WHERE user_id = $1;

-- =================================================================================
-- RECOMMENDATION SESSION HISTORY QUERIES
-- =================================================================================

-- name: GetRecommendationSessions :many
SELECT 
    session_id,
    user_id,
    requested_types,
    meal_type,
    food_category_codes,
    food_preferences,
    activity_type_codes,
    activity_preferences,
    insights_question,
    analysis_summary,
    insights_response,
    latest_glucose_value,
    latest_hba1c,
    user_condition_id,
    ai_model_used,
    ai_confidence_score,
    overall_feedback,
    feedback_notes,
    created_at,
    expires_at
FROM recommendation_sessions
WHERE user_id = $1
    AND (
        sqlc.arg(include_expired)::BOOLEAN = true 
        OR expires_at > NOW()
    )
ORDER BY created_at DESC
LIMIT sqlc.arg(limit_count)::INTEGER
OFFSET sqlc.arg(offset_count)::INTEGER;

-- name: GetRecommendationSessionsCount :one
SELECT COUNT(*)
FROM recommendation_sessions
WHERE user_id = $1
    AND (
        sqlc.arg(include_expired)::BOOLEAN = true 
        OR expires_at > NOW()
    );

-- name: GetSessionFoodMetrics :one
SELECT 
    COUNT(*) as foods_count,
    COUNT(*) FILTER (WHERE was_purchased = true) as foods_purchased,
    COUNT(*) FILTER (WHERE was_added_to_cart = true) as foods_added_to_cart,
    AVG(user_rating) FILTER (WHERE user_rating IS NOT NULL) as avg_rating,
    AVG(glucose_spike_after_eating) FILTER (WHERE glucose_spike_after_eating IS NOT NULL) as avg_glucose_spike
FROM recommended_foods
WHERE session_id = $1;

-- name: GetSessionActivityMetrics :one
SELECT 
    COUNT(*) as activities_count,
    COUNT(*) FILTER (WHERE was_completed = true) as activities_completed,
    AVG(user_rating) FILTER (WHERE user_rating IS NOT NULL) as avg_rating,
    AVG(glucose_change_after_activity) FILTER (WHERE glucose_change_after_activity IS NOT NULL) as avg_glucose_change
FROM recommended_activities
WHERE session_id = $1;

-- name: ExpireRecommendationSession :exec
UPDATE recommendation_sessions
SET expires_at = NOW()
WHERE session_id = $1;

-- name: GetRecentSessionsByCondition :many
-- Get recent sessions for users with similar health conditions
-- Useful for analytics and learning patterns
SELECT 
    rs.session_id,
    rs.user_id,
    rs.user_condition_id,
    rs.meal_type,
    rs.food_category_codes,
    rs.created_at,
    COUNT(DISTINCT rf.food_id) as foods_count,
    COUNT(DISTINCT rf.food_id) FILTER (WHERE rf.was_purchased = true) as foods_purchased,
    AVG(rf.user_rating) FILTER (WHERE rf.user_rating IS NOT NULL) as avg_food_rating
FROM recommendation_sessions rs
LEFT JOIN recommended_foods rf ON rs.session_id = rf.session_id
WHERE rs.user_condition_id = sqlc.arg(condition_id)::INTEGER
    AND rs.created_at >= NOW() - INTERVAL '30 days'
    AND rs.expires_at > NOW()
GROUP BY rs.session_id
ORDER BY rs.created_at DESC
LIMIT 50;

-- name: GetSessionsByDateRange :many
-- Get user's sessions within a date range
SELECT 
    session_id,
    created_at,
    requested_types,
    meal_type,
    analysis_summary,
    overall_feedback
FROM recommendation_sessions
WHERE user_id = $1
    AND created_at >= sqlc.arg(start_date)::TIMESTAMPTZ
    AND created_at <= sqlc.arg(end_date)::TIMESTAMPTZ
ORDER BY created_at DESC;

-- name: GetSessionEffectivenessStats :one
-- Get overall effectiveness statistics for a user
SELECT 
    COUNT(DISTINCT rs.session_id) as total_sessions,
    COUNT(DISTINCT rf.food_id) as total_food_recommendations,
    COUNT(DISTINCT rf.food_id) FILTER (WHERE rf.was_purchased = true) as foods_purchased,
    COUNT(DISTINCT ra.activity_id) as total_activity_recommendations,
    COUNT(DISTINCT ra.activity_id) FILTER (WHERE ra.was_completed = true) as activities_completed,
    AVG(rf.user_rating) FILTER (WHERE rf.user_rating IS NOT NULL) as avg_food_rating,
    AVG(ra.user_rating) FILTER (WHERE ra.user_rating IS NOT NULL) as avg_activity_rating,
    AVG(rf.glucose_spike_after_eating) FILTER (WHERE rf.glucose_spike_after_eating IS NOT NULL) as avg_glucose_spike
FROM recommendation_sessions rs
LEFT JOIN recommended_foods rf ON rs.session_id = rf.session_id
LEFT JOIN recommended_activities ra ON rs.session_id = ra.session_id
WHERE rs.user_id = $1
    AND rs.created_at >= NOW() - INTERVAL '90 days';

-- name: SearchRecommendationSessions :many
-- Search sessions by various criteria
SELECT 
    rs.session_id,
    rs.created_at,
    rs.requested_types,
    rs.meal_type,
    rs.food_category_codes,
    rs.analysis_summary,
    rs.overall_feedback
FROM recommendation_sessions rs
WHERE rs.user_id = $1
    AND (
        sqlc.arg(search_query)::TEXT IS NULL
        OR rs.analysis_summary ILIKE '%' || sqlc.arg(search_query) || '%'
        OR sqlc.arg(search_query) = ANY(rs.requested_types)
        OR sqlc.arg(search_query) = ANY(rs.food_category_codes)
        OR rs.meal_type = sqlc.arg(search_query)
    )
    AND (
        sqlc.arg(feedback_filter)::TEXT IS NULL
        OR rs.overall_feedback = sqlc.arg(feedback_filter)
    )
ORDER BY rs.created_at DESC
LIMIT 50;

/* ====================================================================
                           Unused Queries
==================================================================== */
-- name: GetUserActiveRefreshTokens :many
SELECT * FROM users_refresh_tokens
WHERE user_id = $1 
  AND revoked_at IS NULL 
  AND expires_at > CURRENT_TIMESTAMP
ORDER BY created_at DESC;

-- name: UpdateRefreshTokenReplacement :exec
UPDATE users_refresh_tokens
SET replaced_by_token_id = $2
WHERE id = $1;

-- name: GetAuthLogsByUserID :many
SELECT * FROM logs_auth
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: GetAuthLogsByCategory :many
SELECT * FROM logs_auth
WHERE log_category = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: GetAuthLogsByDateRange :many
SELECT * FROM logs_auth
WHERE created_at BETWEEN $1 AND $2
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: GetFailedLoginAttempts :many
SELECT * FROM logs_auth
WHERE log_category = 'login'
  AND log_action = 'login_failed'
  AND created_at > $1
ORDER BY created_at DESC;

-- name: GetRecentAuthActivity :many
SELECT * FROM logs_auth
WHERE user_id = $1
  AND created_at > $2
ORDER BY created_at DESC
LIMIT $3;

-- name: DeleteOldAuthLogs :exec
DELETE FROM logs_auth
WHERE created_at < $1;

-- name: VerifyOTPAtomic :one
SELECT * FROM verify_otp_atomic($1, $2);