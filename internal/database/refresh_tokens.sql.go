// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: refresh_tokens.sql

package database

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

const createRefreshToken = `-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    $3,
    NULL
)
RETURNING token, created_at, updated_at, user_id, expires_at, revoked_at
`

type CreateRefreshTokenParams struct {
	Token     string
	UserID    uuid.UUID
	ExpiresAt sql.NullTime
}

func (q *Queries) CreateRefreshToken(ctx context.Context, arg CreateRefreshTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, createRefreshToken, arg.Token, arg.UserID, arg.ExpiresAt)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getRefreshToken = `-- name: GetRefreshToken :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at FROM refresh_tokens WHERE token=$1
`

func (q *Queries) GetRefreshToken(ctx context.Context, token string) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getRefreshToken, token)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getRefreshTokenByUserID = `-- name: GetRefreshTokenByUserID :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at FROM refresh_tokens WHERE user_id=$1
`

func (q *Queries) GetRefreshTokenByUserID(ctx context.Context, userID uuid.UUID) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getRefreshTokenByUserID, userID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getUserFromRefreshToken = `-- name: GetUserFromRefreshToken :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red FROM users
WHERE id=(SELECT user_id FROM refresh_tokens WHERE token=$1)
`

func (q *Queries) GetUserFromRefreshToken(ctx context.Context, token string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserFromRefreshToken, token)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const revokeRefreshToken = `-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens 
SET
updated_at=NOW(),
revoked_at=NOW()
WHERE token=$1
`

func (q *Queries) RevokeRefreshToken(ctx context.Context, token string) error {
	_, err := q.db.ExecContext(ctx, revokeRefreshToken, token)
	return err
}
