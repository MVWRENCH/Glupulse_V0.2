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
    user_accounttype
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
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

-- name: GetUserByProviderID :one
SELECT * FROM users
WHERE user_provider = $1 AND user_provider_user_id = $2;

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