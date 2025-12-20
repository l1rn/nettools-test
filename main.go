package main

import (
	"fmt"
	"nettools/capture"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var packetChan = make(chan map[string]interface{}, 1000)

func startPacketForward() {
	for packet := range packetChan {
		msg := WebSocketMessage{
			Type: "packet",
			Data: packet,
		}
		hub.broadcast(msg)
	}
}

func main() {
	// go startPacketForward()
	// go startServer()

	iface := capture.ChooseInterface()
	time.Sleep(100 * time.Millisecond)

	fmt.Println("Start capturing...")
	capture.Start(iface, func(p capture.Packet) {
		fmt.Printf(
			"%s %s:%d -> %s:%d SNI=%s\n",
			p.Proto,
			p.SrcIP, p.SrcPort,
			p.DstIP, p.DstPort,
			p.SNI,
		)
	})

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("End capturing...")
}
