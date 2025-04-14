package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"

	"os"
	"time"

	"database/sql"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/jukkapekkaj/chirpy/internal/auth"
	"github.com/jukkapekkaj/chirpy/internal/database"
	_ "github.com/lib/pq"
)

type User struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"-"`
	Token          string    `json:"token"`
	RefreshToken   string    `json:"refresh_token"`
	IsChirpyRed    bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

const addr = "localhost:8080"

type apiConfig struct {
	fileserverHits   atomic.Int32
	db               *database.Queries
	platform         string
	jwt_token_secret string
	polka_api_key    string
}

func main() {
	godotenv.Load(".env")
	dbURL := os.Getenv("DB_URL")
	environmentPlatform := os.Getenv("PLATFORM")
	jwt_secret := os.Getenv("JWT_TOKEN_SECRET")
	polka_key := os.Getenv("POLKA_KEY")
	//fmt.Println(dbURL)

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Couldnt open connection to database: %s", err)
		os.Exit(1)
	}

	apiCfg := apiConfig{
		fileserverHits:   atomic.Int32{},
		platform:         environmentPlatform,
		jwt_token_secret: jwt_secret,
		polka_api_key:    polka_key,
	}

	apiCfg.db = database.New(db)

	smux := http.NewServeMux()
	server := &http.Server{Handler: smux, Addr: addr}

	//smux.Handle("/assets/", http.FileServer(http.Dir(".")))
	fileServerHandler := http.FileServer(http.Dir("."))
	smux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(fileServerHandler)))
	smux.HandleFunc("GET /api/healthz", healthCheckHandler)
	smux.HandleFunc("GET /admin/metrics", apiCfg.metricsCheckHandler)
	smux.HandleFunc("POST /admin/reset", apiCfg.resetMetricsHandler)
	smux.HandleFunc("POST /api/validate_chirp", handlerValidateChirp)
	smux.HandleFunc("POST /api/users", apiCfg.handlerAddUser)
	smux.HandleFunc("POST /api/chirps", apiCfg.handlerAddChirp)
	smux.HandleFunc("GET /api/chirps", apiCfg.handlerGetChirps)
	smux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetChirp)
	smux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	smux.HandleFunc("POST /api/refresh", apiCfg.handlerRefresh)
	smux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)
	smux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateUser)
	smux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerDeleteChirp)
	smux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerUpdateUserToChirpy)

	fmt.Println("Server listening on", addr)
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}

}

func healthCheckHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Add("Content-Type", "text/plain; charset=utf-8")
	res.WriteHeader(200)
	res.Write([]byte("OK"))

}

func (cfg *apiConfig) metricsCheckHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Add("Content-Type", "text/html; charset=utf-8")
	res.WriteHeader(200)
	res.Write([]byte(fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) resetMetricsHandler(res http.ResponseWriter, req *http.Request) {
	if cfg.platform != "dev" {
		res.WriteHeader(403)
	} else {
		cfg.fileserverHits.Add(1)
		err := cfg.db.DeleteUsers(req.Context())
		if err != nil {
			fmt.Printf("Couldnt delete users: %s", err)
			res.WriteHeader(500)
			res.Write([]byte(`{"error": "Something went wrong"}`))
			return
		}

		cfg.fileserverHits.Store(0)
		res.WriteHeader(http.StatusOK)
		res.Write([]byte("Hits reset to 0"))

	}

}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)

	})
}

func handlerValidateChirp(res http.ResponseWriter, req *http.Request) {
	type bodyStruct struct {
		Body string `json:"body"`
	}

	var body bodyStruct

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&body)
	if err != nil {
		fmt.Printf("Error decoding parameters %s", err)
		res.WriteHeader(500)
		res.Write([]byte(`{"error": "Something went wrong"}`))
		return
	}

	if len(body.Body) > 140 {
		res.WriteHeader(400)
		res.Write([]byte(`{"error": "Chirp is too long"}`))
		return
	}

	filteredWord := filterWords(body.Body)
	res.Write([]byte(fmt.Sprintf(`{"cleaned_body": "%s"}`, filteredWord)))
}

func filterWords(s string) string {
	bad_words := []string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}

	newWords := make([]string, 0)
	for _, w := range strings.Split(s, " ") {
		lowerWord := strings.ToLower(w)
		if slices.Contains(bad_words, lowerWord) {
			newWords = append(newWords, "****")
		} else {
			newWords = append(newWords, w)
		}
	}
	return strings.Join(newWords, " ")

}

func (cfg *apiConfig) middlewarePassConfig(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerAddUser(res http.ResponseWriter, req *http.Request) {

	type inputBody struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	var input inputBody

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&input)
	if err != nil {
		respondWithError(res, 400, "Something went wrong", err)
		return
	}

	hashedPassword, err := auth.HashPassword(input.Password)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}
	user, err := cfg.db.CreateUser(req.Context(), database.CreateUserParams{
		Email:          input.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}
	respondWithJSON(res, 201, User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: false,
	})
	/*
		res.WriteHeader(201)
		res.Write([]byte(fmt.Sprintf(`
		{"id": "%s",
		"created_at": "%s",
		"updated_at": "%s",
		"email": "%s"}
		`, user.ID, user.CreatedAt.Format(time.RFC3339), user.UpdatedAt.Format(time.RFC3339), user.Email)))
	*/

}

func (cfg *apiConfig) handlerAddChirp(res http.ResponseWriter, req *http.Request) {

	type inputBody struct {
		Body   string    `json:"body"`
		UserId uuid.UUID `json:"user_id"`
	}

	var input inputBody

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&input)
	if err != nil {
		fmt.Printf("Error decoding parameters %s", err)
		res.WriteHeader(400)
		res.Write([]byte(`{"error": "Something went wrong"}`))
		return
	}

	// Validate JWT token
	tokenAsString, err := auth.GetBearerToken(req.Header)
	//fmt.Println(tokenAsString)
	if err != nil {
		respondWithError(res, http.StatusUnauthorized, "", err)
		return
	}
	userId, err := auth.ValidateJWT(tokenAsString, cfg.jwt_token_secret)
	if err != nil {
		respondWithError(res, http.StatusUnauthorized, "", err)
		return
	}
	/*
		if userId.String() != input.UserId.String() {
			respondWithError(res, http.StatusUnauthorized, "", err)
			return
		}
	*/

	chirp, err := cfg.db.CreateChirp(req.Context(), database.CreateChirpParams{
		Body:   input.Body,
		UserID: userId,
	})
	if err != nil {
		fmt.Printf("Error creating chirp %s", err)
		res.WriteHeader(500)
		res.Write([]byte(`{"error": "Something went wrong"}`))
		return
	}
	res.WriteHeader(201)
	res.Write([]byte(fmt.Sprintf(`
		{"id": "%s",
		"created_at": "%s",
		"updated_at": "%s",
		"body": "%s",
		"user_id": "%s"}
		`, chirp.ID, chirp.CreatedAt.Format(time.RFC3339), chirp.UpdatedAt.Format(time.RFC3339), chirp.Body, chirp.UserID)))

}

func (cfg *apiConfig) handlerGetChirps(res http.ResponseWriter, req *http.Request) {
	author_id := req.URL.Query().Get("author_id")
	sortOption := req.URL.Query().Get("sort")
	listedChirps := make([]database.Chirp, 0)
	if author_id == "" {
		chirps, err := cfg.db.GetChirps(req.Context())
		if err != nil {
			respondWithError(res, 500, "Something went wrong", err)
			return
		}
		listedChirps = chirps
	} else {
		userID, err := uuid.Parse(author_id)
		if err != nil {
			respondWithError(res, 500, "Something went wrong", err)
			return
		}
		chirps, err := cfg.db.GetChirpsByAuthor(req.Context(), userID)
		if err != nil {
			respondWithError(res, 500, "Something went wrong", err)
			return
		}
		listedChirps = chirps
	}

	if sortOption == "desc" {
		slices.Reverse(listedChirps)
	}

	main_chirps := make([]Chirp, 0)
	for _, c := range listedChirps {
		main_chirps = append(main_chirps, Chirp{
			ID:        c.ID,
			CreatedAt: c.CreatedAt,
			UpdatedAt: c.CreatedAt,
			Body:      c.Body,
			UserID:    c.UserID,
		})
	}
	respondWithJSON(res, 200, main_chirps)
}

func (cfg *apiConfig) handlerGetChirp(res http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		respondWithError(res, 401, "Invalid ID string format", err)
		return
	}
	chirp, err := cfg.db.GetChirp(req.Context(), id)
	if err != nil {
		b := make([]byte, 16)
		empty_uuid, err := uuid.FromBytes(b)
		if err != nil {
			respondWithError(res, 500, "Something went wrong", err)
		} else if chirp.ID == empty_uuid {
			respondWithError(res, 404, "", nil)
		} else {
			respondWithError(res, 500, "Something went wrong", err)
		}
		return
	}

	respondWithJSON(res, http.StatusOK, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})

}

func (cfg *apiConfig) handlerLogin(res http.ResponseWriter, req *http.Request) {
	type inputBody struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	var input inputBody

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&input)
	if err != nil {
		respondWithError(res, 400, "Something went wrong", err)
		return
	}

	user, err := cfg.db.GetUserByEmail(req.Context(), input.Email)
	if err != nil {
		respondWithError(res, 401, "incorrect email or password", err)
		return
	}
	err = auth.CheckPasswordHash(input.Password, user.HashedPassword)
	if err != nil {
		respondWithError(res, 401, "incorrect email or password", err)
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwt_token_secret, time.Hour)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	refresh_token, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	expireTime := sql.NullTime{
		Time:  time.Now().Add(time.Hour * 24 * 60),
		Valid: true,
	}
	_, err = cfg.db.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
		Token:     refresh_token,
		UserID:    user.ID,
		ExpiresAt: expireTime,
	})

	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	respondWithJSON(res, 200, User{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refresh_token,
		IsChirpyRed:  user.IsChirpyRed,
	})

	/*
		res.WriteHeader(201)
		res.Write([]byte(fmt.Sprintf(`
		{"id": "%s",
		"created_at": "%s",
		"updated_at": "%s",
		"email": "%s"}
		`, user.ID, user.CreatedAt.Format(time.RFC3339), user.UpdatedAt.Format(time.RFC3339), user.Email)))
	*/

}

func (cfg *apiConfig) handlerRefresh(res http.ResponseWriter, req *http.Request) {
	fmt.Println(req.Method, req.URL.Path, req.Header, req.Body)
	refreshTokenAsString, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(res, 400, "Invalid request, token missing", err)
		return
	}
	//fmt.Println(refreshTokenAsString)

	token, err := cfg.db.GetRefreshToken(req.Context(), refreshTokenAsString)
	if err != nil {
		if token.Token == "" {
			respondWithError(res, 401, "Token not found", err)
			return
		}
		respondWithError(res, 500, "Something went wrong", err)
		return
	}
	if token.RevokedAt.Valid {
		respondWithError(res, 401, "Token expired", nil)
		return
	}
	if time.Now().After(token.ExpiresAt.Time) {
		respondWithError(res, 401, "Token expired", nil)
		return
	} else {
		fmt.Println("Refresh token is still valid, not expired")
	}

	// Get user who owns refresh token
	user, err := cfg.db.GetUserFromRefreshToken(req.Context(), token.Token)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	// Create new access token for user and send it back
	newJwtToken, err := auth.MakeJWT(user.ID, cfg.jwt_token_secret, time.Hour)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	respondWithJSON(res, 200, struct {
		Token string `json:"token"`
	}{
		Token: newJwtToken,
	})

}

func (cfg *apiConfig) handlerRevoke(res http.ResponseWriter, req *http.Request) {
	fmt.Println(req.Method, req.URL.Path, req.Header, req.Body)
	refreshTokenAsString, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(res, 400, "Invalid request, token missing", err)
		return
	}
	token, err := cfg.db.GetRefreshToken(req.Context(), refreshTokenAsString)
	if err != nil {
		if token.Token == "" {
			respondWithError(res, 401, "Token not found", err)
			return
		}
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	err = cfg.db.RevokeRefreshToken(req.Context(), token.Token)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	res.WriteHeader(204)
}

func (cfg *apiConfig) handlerUpdateUser(res http.ResponseWriter, req *http.Request) {
	//fmt.Println(req.Method, req.URL.Path, req.Header, req.Body)
	type input struct {
		NewPassword string `json:"password"`
		NewEmail    string `json:"email"`
	}

	var newValues input

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&newValues)
	if err != nil {
		respondWithError(res, 400, "Invalid request", err)
		return
	}

	accessToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(res, 401, "Invalid request, token missing", err)
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.jwt_token_secret)
	if err != nil {
		respondWithError(res, 401, "Invalid token", err)
		return
	}

	refreshToken, err := cfg.db.GetRefreshTokenByUserID(req.Context(), userID)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	newHashedPassword, err := auth.HashPassword(newValues.NewPassword)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	err = cfg.db.UpdateUseInformation(req.Context(), database.UpdateUseInformationParams{
		Email:          newValues.NewEmail,
		HashedPassword: newHashedPassword,
		ID:             userID,
	})
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	user, err := cfg.db.GetUserById(req.Context(), userID)
	if err != nil {
		respondWithError(res, 401, "Invalid token", err)
		return
	}

	respondWithJSON(res, 200, User{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        accessToken,
		RefreshToken: refreshToken.Token,
		IsChirpyRed:  user.IsChirpyRed,
	})
}

func (cfg *apiConfig) handlerDeleteChirp(res http.ResponseWriter, req *http.Request) {
	accessToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(res, 401, "Invalid request, token missing", err)
		return
	}
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		respondWithError(res, 401, "Invalid ID string format", err)
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.jwt_token_secret)
	if err != nil {
		respondWithError(res, 401, "Invalid token", err)
		return
	}

	chirp, err := cfg.db.GetChirp(req.Context(), chirpID)
	if err != nil {
		b := make([]byte, 16)
		empty_uuid, err := uuid.FromBytes(b)
		if err != nil {
			respondWithError(res, 500, "Something went wrong", err)
		} else if chirp.ID == empty_uuid {
			respondWithError(res, 404, "", nil)
		} else {
			respondWithError(res, 500, "Something went wrong", err)
		}
		return
	}

	if chirp.UserID != userID {
		respondWithError(res, 403, "Unauthorized", nil)
		return
	}

	err = cfg.db.DeleteChirp(req.Context(), chirp.ID)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	res.WriteHeader(204)

}

func (cfg *apiConfig) handlerUpdateUserToChirpy(res http.ResponseWriter, req *http.Request) {
	type input struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	var inputData input
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&inputData)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	apiKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		respondWithError(res, 401, "No API key found in HTTP headers", err)
		return
	}

	if apiKey != cfg.polka_api_key {
		respondWithError(res, 401, "Invalid API key", err)
		return
	}

	if inputData.Event != "user.upgraded" {
		respondWithError(res, 204, "Invalid event type", nil)
		return
	}
	userID, err := uuid.Parse(inputData.Data.UserID)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}
	user, err := cfg.db.GetUserById(req.Context(), userID)
	if err != nil {
		if user.ID == uuid.Nil {
			respondWithError(res, 404, "User not found", err)
			return
		}
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	err = cfg.db.UpdateUserToChirpyRed(req.Context(), user.ID)
	if err != nil {
		respondWithError(res, 500, "Something went wrong", err)
		return
	}

	res.WriteHeader(204)
}

func respondWithError(res http.ResponseWriter, code int, msg string, err error) {
	if err != nil {
		fmt.Println("respondWithError:", err)
	}
	if code > 499 {
		fmt.Printf("Responding with 5XX error: %s", msg)
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	respondWithJSON(res, code, errorResponse{
		Error: msg,
	})
}

func respondWithJSON(res http.ResponseWriter, code int, payload interface{}) {
	res.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		res.WriteHeader(500)
		return
	}
	res.WriteHeader(code)
	res.Write(dat)
}
