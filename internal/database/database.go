/*
Package database provides a thread-safe service for managing PostgreSQL
connection pools using pgx/v5 and sqlc-generated queries.
*/
package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/joho/godotenv/autoload"
)

// Service defines the interface for database lifecycle and health management.
type Service interface {
	// Health returns a diagnostic report of the connection pool status.
	Health() map[string]string
	// Close gracefully terminates all connections in the pool.
	Close()
	// Queries returns the sqlc-generated query set for type-safe operations.
	Queries() *Queries
}

type service struct {
	pool *pgxpool.Pool
	q    *Queries
}

var (
	dbInstance Service
	dbOnce     sync.Once
	// Dbpool is exported for packages that require direct pool access.
	Dbpool *pgxpool.Pool
)

// NewService initializes a singleton database service. It uses sync.Once to
// ensure thread-safe initialization and configures the pool for production use.
func NewService() Service {
	dbOnce.Do(func() {
		// Load configuration from environment variables
		user := os.Getenv("BLUEPRINT_DB_USERNAME")
		password := os.Getenv("BLUEPRINT_DB_PASSWORD")
		host := os.Getenv("BLUEPRINT_DB_HOST")
		port := os.Getenv("BLUEPRINT_DB_PORT")
		dbName := os.Getenv("BLUEPRINT_DB_DATABASE")
		schema := os.Getenv("BLUEPRINT_DB_SCHEMA")

		connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&search_path=%s",
			user, password, host, port, dbName, schema)

		// Parse the connection string into a config struct
		config, err := pgxpool.ParseConfig(connStr)
		if err != nil {
			log.Fatalf("Failed to parse database config: %v", err)
		}

		// Optimization: Configure pool settings for high-concurrency
		config.MaxConns = 25                      // Maximum connections in the pool
		config.MinConns = 5                       // Minimum idle connections to maintain
		config.MaxConnLifetime = 30 * time.Minute // Maximum age of a connection
		config.MaxConnIdleTime = 5 * time.Minute  // Maximum idle time before closing

		// Fix: Use NewWithConfig instead of the non-existent NewConfig
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			log.Fatalf("Unable to create connection pool: %v", err)
		}

		// Initialize package-level variables and types
		Dbpool = pool
		queries := New(pool)

		dbInstance = &service{
			pool: pool,
			q:    queries,
		}
	})

	return dbInstance
}

// Queries returns the sqlc-generated query set associated with this service.
func (s *service) Queries() *Queries {
	return s.q
}

// Health performs a ping and collects telemetry stats from the connection pool.
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stats := make(map[string]string)

	if err := s.pool.Ping(ctx); err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("ping failed: %v", err)
		return stats
	}

	pStats := s.pool.Stat()
	stats["status"] = "up"
	stats["total_conns"] = strconv.Itoa(int(pStats.TotalConns()))
	stats["idle_conns"] = strconv.Itoa(int(pStats.IdleConns()))
	stats["acquired_conns"] = strconv.Itoa(int(pStats.AcquiredConns()))
	stats["max_conns"] = strconv.Itoa(int(pStats.MaxConns()))
	stats["acquire_duration_ms"] = strconv.FormatInt(pStats.AcquireDuration().Milliseconds(), 10)

	// Saturation alerts
	if pStats.AcquiredConns() > (pStats.MaxConns() * 8 / 10) {
		stats["warning"] = "Pool saturation is above 80%"
	}

	return stats
}

// Close logs the shutdown event and terminates the pool.
func (s *service) Close() {
	log.Println("Disconnected from database pool.")
	s.pool.Close()
}
