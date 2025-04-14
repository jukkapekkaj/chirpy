-- +goose Up
CREATE TABLE refresh_tokens (
    token TEXT PRIMARY KEY,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);


-- +goose Down
DROP TABLE refresh_tokens;