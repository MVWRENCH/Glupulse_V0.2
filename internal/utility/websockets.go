/*
Package utility provides shared helper functions and cross-domain orchestration
logic, specifically managing real-time WebSocket communication for Sellers and Admins.
*/
package utility

import (
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

var (
	// SellerClients maps Seller UUIDs to their active WebSocket connections.
	SellerClients = make(map[string]*websocket.Conn)
	// SellerClientsMu ensures thread-safe access to the SellerClients map.
	SellerClientsMu sync.RWMutex

	// AdminClients maps Admin UUIDs to their active WebSocket connections.
	AdminClients = make(map[string]*websocket.Conn)
	// AdminClientsMu ensures thread-safe access to the AdminClients map.
	AdminClientsMu sync.RWMutex

	// Upgrader configures the transition from HTTP to the WebSocket protocol.
	// CheckOrigin is currently set to allow all origins for development flexibility.
	Upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
)

/* ====================================================================
                        SELLER WEBSOCKET LOGIC
   Manages targeted updates for specific merchants (e.g. New Orders).
==================================================================== */

// RegisterSellerClient associates an active WebSocket connection with a specific Seller ID.
func RegisterSellerClient(sellerID string, conn *websocket.Conn) {
	SellerClientsMu.Lock()
	defer SellerClientsMu.Unlock()
	SellerClients[sellerID] = conn
	log.Info().Str("seller_id", sellerID).Msg("WS: Seller instance connected")
}

// UnregisterSellerClient removes a Seller's connection from the registry, usually called on disconnect.
func UnregisterSellerClient(sellerID string) {
	SellerClientsMu.Lock()
	defer SellerClientsMu.Unlock()
	if _, ok := SellerClients[sellerID]; ok {
		delete(SellerClients, sellerID)
		log.Info().Str("seller_id", sellerID).Msg("WS: Seller instance disconnected")
	}
}

// TriggerSellerUpdate sends a refresh signal to a specific merchant's frontend.
// If the connection is broken, it automatically unregisters the client.
func TriggerSellerUpdate(sellerID string) {
	SellerClientsMu.Lock()
	defer SellerClientsMu.Unlock()

	conn, ok := SellerClients[sellerID]
	if !ok {
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte("REFRESH")); err != nil {
		log.Error().Err(err).Str("seller_id", sellerID).Msg("WS: Transmission failed, purging connection")
		conn.Close()
		delete(SellerClients, sellerID)
	}
}

/* ====================================================================
                        ADMIN WEBSOCKET LOGIC
   Manages global system health broadcasting and security alerts.
==================================================================== */

// RegisterAdminClient associates an active administrative connection with an Admin ID.
func RegisterAdminClient(adminID string, conn *websocket.Conn) {
	AdminClientsMu.Lock()
	defer AdminClientsMu.Unlock()
	AdminClients[adminID] = conn
	log.Info().Str("admin_id", adminID).Msg("WS: Admin terminal connected")
}

// UnregisterAdminClient removes an administrative terminal from the active registry.
func UnregisterAdminClient(adminID string) {
	AdminClientsMu.Lock()
	defer AdminClientsMu.Unlock()
	if _, ok := AdminClients[adminID]; ok {
		delete(AdminClients, adminID)
		log.Info().Str("admin_id", adminID).Msg("WS: Admin terminal disconnected")
	}
}

// BroadcastToAdmins transmits a message to all currently connected administrative terminals.
// This is used for real-time system metrics, security logs, and task notifications.
func BroadcastToAdmins(message string) {
	AdminClientsMu.Lock()
	defer AdminClientsMu.Unlock()

	//
	for adminID, conn := range AdminClients {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			log.Error().Err(err).Str("admin_id", adminID).Msg("WS: Admin broadcast failed, removing client")
			conn.Close()
			delete(AdminClients, adminID)
		}
	}
}
