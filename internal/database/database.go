package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"
)

// Service represents a service that interacts with a database.
type Service interface {
	// Health returns a map of health status information.
	// The keys and values in the map are service-specific.
	Health() map[string]string

	// Close terminates the database connection.
	// It returns an error if the connection cannot be closed.
	Close()

	Queries() *Queries
}

type service struct {
	Dbpool *pgxpool.Pool
	q      *Queries
}

// Queries implements Service.
func (s *service) Queries() *Queries {
	return s.q
}

var (
	database   = os.Getenv("BLUEPRINT_DB_DATABASE")
	password   = os.Getenv("BLUEPRINT_DB_PASSWORD")
	username   = os.Getenv("BLUEPRINT_DB_USERNAME")
	port       = os.Getenv("BLUEPRINT_DB_PORT")
	host       = os.Getenv("BLUEPRINT_DB_HOST")
	schema     = os.Getenv("BLUEPRINT_DB_SCHEMA")
	dbInstance *service

	Dbpool *pgxpool.Pool
)

func NewService() Service {
	// Reuse Connection
	if dbInstance != nil {
		return dbInstance
	}
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&search_path=%s", username, password, host, port, database, schema)

	// FIX: Assign the connection pool to our new exported variable.
	var err error
	Dbpool, err = pgxpool.New(context.Background(), connStr)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v\n", err)
	}

	// Create a new Queries object from the sqlc-generated code.
	q := New(Dbpool)

	dbInstance = &service{
		// FIX: Use the now-initialized package-level variable.
		Dbpool: Dbpool,
		q:      q,
	}
	return dbInstance
}

// Health checks the health of the database connection.
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(map[string]string)

	if err := s.Dbpool.Ping(ctx); err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("db down: %v", err)
		log.Printf("db down: %v", err)
		return stats
	}

	poolStats := s.Dbpool.Stat()
	stats["status"] = "up"
	stats["total_conns"] = strconv.Itoa(int(poolStats.TotalConns()))
	stats["idle_conns"] = strconv.Itoa(int(poolStats.IdleConns()))
	stats["acquired_conns"] = strconv.Itoa(int(poolStats.AcquiredConns()))
	stats["max_conns"] = strconv.Itoa(int(poolStats.MaxConns()))
	stats["acquire_count"] = strconv.FormatInt(poolStats.AcquireCount(), 10)
	stats["acquire_duration_ms"] = strconv.FormatInt(poolStats.AcquireDuration().Milliseconds(), 10)
	stats["empty_acquire_count"] = strconv.FormatInt(poolStats.EmptyAcquireCount(), 10)
	stats["canceled_acquire_count"] = strconv.FormatInt(poolStats.CanceledAcquireCount(), 10)

	if poolStats.AcquiredConns() > (poolStats.MaxConns() * 8 / 10) { // 80% capacity
		stats["message"] = "The database connection pool is experiencing heavy load."
	}
	if poolStats.EmptyAcquireCount() > 0 {
		stats["message"] = "The application has tried to acquire a connection from an empty pool. Consider increasing max connections."
	}

	return stats
}

// Close closes the database connection.
func (s *service) Close() {
	log.Printf("Disconnected from database: %s", database)
	s.Dbpool.Close()
}
