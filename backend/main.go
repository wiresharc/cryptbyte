package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"file2file/handlers"
	"file2file/middleware"
	"file2file/storage"
)

func envInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func main() {
	uploadDir := "./uploads"
	os.MkdirAll(uploadDir, 0755)

	maxStorage := envInt64("MAX_STORAGE_BYTES", 200*1024*1024*1024)
	// the frontend caps plaintext at 2 GiB but this limit applies to the
	// ciphertext, which is always larger, so leave room for the per chunk auth
	// tag and header or the top few KB of the range fail with a 413
	maxFile := envInt64("MAX_UPLOAD_BYTES", 2*1024*1024*1024+16*1024*1024)
	maxChunk := envInt64("MAX_CHUNK_BYTES", 90*1024*1024)
	quotaBytes := envInt64("UPLOAD_QUOTA_BYTES", 4*1024*1024*1024)
	maxConcurrent := int(envInt64("MAX_CONCURRENT_UPLOADS", 4))
	// a part is at most 88 MiB, so anything past this is a dead connection rather
	// than a slow one. the client also gives up on its own after 90s of silence
	readTimeout := time.Duration(envInt64("UPLOAD_READ_TIMEOUT_SECONDS", 600)) * time.Second
	writeTimeout := time.Duration(envInt64("UPLOAD_WRITE_TIMEOUT_SECONDS", 600)) * time.Second

	store := storage.NewStore(uploadDir, maxStorage)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			store.CleanupExpired()
		}
	}()

	uploadHandler := handlers.NewUploadHandler(store, maxConcurrent, quotaBytes, maxFile, maxChunk, readTimeout, writeTimeout)
	downloadHandler := handlers.NewDownloadHandler(store)
	infoHandler := handlers.NewInfoHandler(store)
	uploadStatus := handlers.NewUploadHandlerStatus(store)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/upload", uploadHandler.Handle)
	mux.HandleFunc("/api/download/", downloadHandler.Handle)
	mux.HandleFunc("/api/info/", infoHandler.Handle)
	mux.HandleFunc("/api/upload/status", uploadStatus.Handle)
	mux.HandleFunc("/api/captcha/token", func(w http.ResponseWriter, r *http.Request) {
		token, err := middleware.GenerateCaptchaToken()
		if err != nil {
			http.Error(w, "captcha unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	})

	var handler http.Handler = mux
	handler = middleware.Logging(handler)
	handler = middleware.RateLimit(handler)
	handler = middleware.CORS(handler)

	// workin on a weeknd like usual

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Println("cryptbyte server starting on :8080")
	log.Fatal(srv.ListenAndServe())
}
