-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email=$1;

-- name: GetUserById :one
SELECT * FROM users WHERE id=$1;

-- name: UpdateUseInformation :exec
UPDATE users SET email=$1, hashed_password=$2, updated_at=NOW() WHERE id=$3;

-- name: UpdateUserToChirpyRed :exec
UPDATE users SET is_chirpy_red=true, updated_at=NOW() WHERE id=$1;