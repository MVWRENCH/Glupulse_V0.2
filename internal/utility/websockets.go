package utility

import (
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

var (
	// SELLER Connections: Map[SellerID] -> Connection
	SellerClients   = make(map[string]*websocket.Conn)
	SellerClientsMu sync.Mutex

	// ADMIN Connections: Map[AdminID] -> Connection
	AdminClients   = make(map[string]*websocket.Conn)
	AdminClientsMu sync.Mutex

	Upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

// ---------------------------
// SELLER LOGIC (Existing)
// ---------------------------

func RegisterSellerClient(sellerID string, conn *websocket.Conn) {
	SellerClientsMu.Lock()
	defer SellerClientsMu.Unlock()
	SellerClients[sellerID] = conn
	log.Info().Str("seller_id", sellerID).Msg("WS: Seller Connected")
}

func UnregisterSellerClient(sellerID string) {
	SellerClientsMu.Lock()
	defer SellerClientsMu.Unlock()
	if _, ok := SellerClients[sellerID]; ok {
		delete(SellerClients, sellerID)
		log.Info().Str("seller_id", sellerID).Msg("WS: Seller Disconnected")
	}
}

func TriggerSellerUpdate(sellerID string) {
	SellerClientsMu.Lock()
	defer SellerClientsMu.Unlock()

	if conn, ok := SellerClients[sellerID]; ok {
		if err := conn.WriteMessage(websocket.TextMessage, []byte("REFRESH")); err != nil {
			log.Error().Err(err).Msg("WS: Failed to message seller, removing")
			conn.Close()
			delete(SellerClients, sellerID)
		}
	}
}

// ---------------------------
// ADMIN LOGIC (New)
// ---------------------------

// RegisterAdminClient adds an admin connection
func RegisterAdminClient(adminID string, conn *websocket.Conn) {
	AdminClientsMu.Lock()
	defer AdminClientsMu.Unlock()
	AdminClients[adminID] = conn
	log.Info().Str("admin_id", adminID).Msg("WS: Admin Connected")
}

// UnregisterAdminClient removes an admin connection
func UnregisterAdminClient(adminID string) {
	AdminClientsMu.Lock()
	defer AdminClientsMu.Unlock()
	if _, ok := AdminClients[adminID]; ok {
		delete(AdminClients, adminID)
		log.Info().Str("admin_id", adminID).Msg("WS: Admin Disconnected")
	}
}

// BroadcastToAdmins sends a message to ALL connected admins
// Use this when a new Seller registers or a new Security Alert happens
func BroadcastToAdmins(message string) {
	AdminClientsMu.Lock()
	defer AdminClientsMu.Unlock()

	for adminID, conn := range AdminClients {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			log.Error().Err(err).Str("admin_id", adminID).Msg("WS: Failed to message admin, removing")
			conn.Close()
			delete(AdminClients, adminID)
		}
	}
}