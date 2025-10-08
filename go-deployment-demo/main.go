package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Config holds application configuration from environment variables
type Config struct {
	Port        string
	Environment string
	Version     string
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status      string    `json:"status"`
	Version     string    `json:"version"`
	Environment string    `json:"environment"`
	Timestamp   time.Time `json:"timestamp"`
}

// MetricsResponse represents basic metrics
type MetricsResponse struct {
	Uptime  string `json:"uptime"`
	Version string `json:"version"`
}

var (
	startTime time.Time
	config    Config
)

func init() {
	startTime = time.Now()
	
	// Load configuration from environment variables (12-factor app)
	config = Config{
		Port:        getEnv("PORT", "8080"),
		Environment: getEnv("ENVIRONMENT", "development"),
		Version:     getEnv("VERSION", "1.0.0"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	// Setup HTTP routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/ready", readinessHandler)
	http.HandleFunc("/metrics", metricsHandler)

	addr := ":" + config.Port
	log.Printf("Starting Go Deployment Demo Server v%s", config.Version)
	log.Printf("Environment: %s", config.Environment)
	log.Printf("Listening on %s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Go Deployment Demo - Version %s\n", config.Version)
	fmt.Fprintf(w, "Environment: %s\n", config.Environment)
	fmt.Fprintf(w, "\nAvailable endpoints:\n")
	fmt.Fprintf(w, "  GET /health   - Health check\n")
	fmt.Fprintf(w, "  GET /ready    - Readiness probe\n")
	fmt.Fprintf(w, "  GET /metrics  - Application metrics\n")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:      "healthy",
		Version:     config.Version,
		Environment: config.Environment,
		Timestamp:   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	// In a real application, you would check dependencies here
	// (database connections, external services, etc.)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ready",
	})
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startTime)
	
	response := MetricsResponse{
		Uptime:  uptime.String(),
		Version: config.Version,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
