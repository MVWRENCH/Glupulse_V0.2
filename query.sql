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
    user_created_at_auth,
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
    user_last_login_at = EXCLUDED.user_last_login_at, -- Menggunakan nilai login time dari EXCLUDED ($8)
    user_updated_at_auth = CURRENT_TIMESTAMP -- Menggunakan CURRENT_TIMESTAMP untuk mencatat pembaruan skema auth
RETURNING *;

-- name: UpdateUserGoogleLink :exec
UPDATE users
SET 
  user_name_auth = $1,
  user_avatar_url = $2,
  user_provider = $3,
  user_provider_user_id = $4,
  user_raw_data = $5,
  user_email_auth = $6,
  user_updated_at_auth = NOW()
WHERE 
  user_id = $7;

-- name: UnlinkGoogleAccount :exec
UPDATE users
SET 
  user_name_auth = NULL,
  user_provider = NULL,
  user_provider_user_id = NULL,
  user_avatar_url = NULL,   -- Clear the avatar linked to Google
  user_raw_data = NULL,     -- Clear the raw data from Google
  user_updated_at_auth = NOW()
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

-- User Addresses
-- name: CreateUserAddress :one
INSERT INTO user_addresses (
    user_id,
    address_line1,
    address_line2,
    address_city,
    address_province,
    address_postalcode,
    address_latitude,
    address_longitude,
    address_label,
    is_default
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
) RETURNING *;

-- name: GetUserAddresses :many
SELECT * FROM user_addresses
WHERE user_id = $1
ORDER BY is_default DESC, address_id DESC;

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
SET user_password = $2,
    user_updated_at_auth = NOW()
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
SET user_email = $2,
    user_updated_at_auth = NOW()
WHERE user_id = $1;

-- name: UpdateUserUsername :exec
UPDATE users
SET user_username = $2,
    user_updated_at_auth = NOW()
WHERE user_id = $1;

-- name: DeleteUser :exec
DELETE FROM users
WHERE user_id = $1;

-- name: VerifyUserEmail :exec
UPDATE users
SET is_email_verified = $2,
    email_verified_at = $3
WHERE user_id = $1;

-- name: CreateHealthData :one
INSERT INTO user_healthdata (
    healthdata_id,
    user_id,
    healthdata_weight,
    healthdata_height,
    healthdata_bmi,
    healthdata_recordtime,
    recorded_by,
    healthdata_bloodpressure,
    healthdata_heartrate,
    healthdata_notes
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING *;

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

-- Unused queries
-- name: GetUserActiveRefreshTokens :many
SELECT * FROM users_refresh_tokens
WHERE user_id = $1 
  AND revoked_at IS NULL 
  AND expires_at > CURRENT_TIMESTAMP
ORDER BY created_at DESC;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM users_refresh_tokens
WHERE expires_at < CURRENT_TIMESTAMP;

-- name: UpdateRefreshTokenReplacement :exec
UPDATE users_refresh_tokens
SET replaced_by_token_id = $2
WHERE id = $1;

-- name: GetUserDefaultAddress :one
SELECT * FROM user_addresses
WHERE user_id = $1 AND is_default = true
LIMIT 1;

-- name: GetAddressByID :one
SELECT * FROM user_addresses
WHERE address_id = $1 AND user_id = $2;

-- name: UpdateUserAddress :one
UPDATE user_addresses
SET
    address_line1 = COALESCE($3, address_line1),
    address_line2 = COALESCE($4, address_line2),
    address_city = COALESCE($5, address_city),
    address_province = COALESCE($6, address_province),
    address_postalcode = COALESCE($7, address_postalcode),
    address_latitude = COALESCE($8, address_latitude),
    address_longitude = COALESCE($9, address_longitude),
    address_label = COALESCE($10, address_label)
WHERE address_id = $1 AND user_id = $2
RETURNING *;

-- name: SetDefaultAddress :exec
UPDATE user_addresses
SET is_default = (address_id = $2)
WHERE user_id = $1;

-- name: DeleteUserAddress :exec
DELETE FROM user_addresses
WHERE address_id = $1 AND user_id = $2;

-- name: CountUserAddresses :one
SELECT COUNT(*) FROM user_addresses
WHERE user_id = $1;

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