package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)


var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type WebSocketMessage struct {
	Type string			`json:type`
	Data interface{}	`json:data`
}

type ConnectionHub struct {
	sync.RWMutex
	clients map[*websocket.Conn]bool
}

var hub = &ConnectionHub{
	clients: make(map[*websocket.Conn]bool),
}

func (h *ConnectionHub) register(client *websocket.Conn){
	h.Lock()
	h.clients[client] = true
	h.Unlock()
	log.Printf("Client connected! Total: %d", len(h.clients))
}

func (h *ConnectionHub) unregister(client *websocket.Conn){
	h.Lock()
	delete(h.clients, client)
	h.Unlock()
	client.Close()
	log.Printf("Client disconnected! Total: %d", len(h.clients))
}

func (h *ConnectionHub) broadcast(msg WebSocketMessage) {
	h.RLock()
	defer h.RUnlock()

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("JSON error marshal: %v", err)
		return
	}

	for client := range h.clients {
		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("Write error: %v", err)
			h.unregister(client)
		}
	}
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade failed: %v", err)
		return
	}

	hub.register(conn)
	defer hub.unregister(conn)

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func startServer() {
	http.HandleFunc("/ws", wsHandler)
 	log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}