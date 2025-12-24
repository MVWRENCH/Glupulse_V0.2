package utility

import (
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// Simple Hub to hold active connections: Map[SellerID] -> Connection
var (
	Clients   = make(map[string]*websocket.Conn)
	ClientsMu sync.Mutex // Mutex to prevent race conditions
	Upgrader  = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// Allow CORS for development
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

// Register a new client connection
func RegisterClient(sellerID string, conn *websocket.Conn) {
	ClientsMu.Lock()
	defer ClientsMu.Unlock()
	Clients[sellerID] = conn
	log.Info().Str("seller_id", sellerID).Msg("WebSocket Client Connected")
}

// Unregister a client (when they close the tab)
func UnregisterClient(sellerID string) {
	ClientsMu.Lock()
	defer ClientsMu.Unlock()
	if _, ok := Clients[sellerID]; ok {
		delete(Clients, sellerID)
		log.Info().Str("seller_id", sellerID).Msg("WebSocket Client Disconnected")
	}
}

// Notify a specific seller to refresh their dashboard
func TriggerDashboardUpdate(sellerID string) {
	ClientsMu.Lock()
	defer ClientsMu.Unlock()

	if conn, ok := Clients[sellerID]; ok {
		// Send a simple text message "REFRESH"
		if err := conn.WriteMessage(websocket.TextMessage, []byte("REFRESH")); err != nil {
			log.Error().Err(err).Msg("Failed to send WS message, removing client")
			conn.Close()
			delete(Clients, sellerID)
		}
	}
}
