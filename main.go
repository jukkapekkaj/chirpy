package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
)

const addr = "localhost:8080"

type apiConfig struct {
	fileserverHits atomic.Int32
}

func main() {

	smux := http.NewServeMux()

	server := &http.Server{Handler: smux, Addr: addr}
	apiCfg := apiConfig{
		fileserverHits: atomic.Int32{},
	}

	//smux.Handle("/assets/", http.FileServer(http.Dir(".")))
	fileServerHandler := http.FileServer(http.Dir("."))
	smux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(fileServerHandler)))
	smux.HandleFunc("GET /api/healthz", healthCheckHandler)
	smux.HandleFunc("GET /admin/metrics", apiCfg.metricsCheckHandler)
	smux.HandleFunc("POST /admin/reset", apiCfg.resetMetricsHandler)
	smux.HandleFunc("POST /api/validate_chirp", handlerValidateChirp)

	fmt.Println("Server listening on", addr)
	err := server.ListenAndServe()
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
	cfg.fileserverHits.Store(0)
	res.WriteHeader(http.StatusOK)
	res.Write([]byte("Hits reset to 0"))
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
