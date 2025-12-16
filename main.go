package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lpcap
#include "capture.h"
#include "bridge.h"
#include <stdlib.h>
#include <netinet/ip.h>
*/
import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

func protoName(info *C.struct_packet_info) string {
	if info.proto == C.IPPROTO_TCP {
		if info.dst_port == 443 || info.src_port == 443 {
			return "TLS"
		}
		if info.dst_port == 80 || info.src_port == 80 {
			return "HTTP"
		}
		return "TCP"
	}
	if info.proto == C.IPPROTO_UDP {
		if info.dst_port == 53 || info.src_port == 53 {
			return "DNS"
		}
		if info.dst_port == 443 || info.src_port == 443 {
			return "QUIC"
		}
		return "UDP"
	}
	return "UNKNOWN"
}

var packetChan = make(chan map[string]interface{}, 1000)
var dnsChan = make(chan string, 1000)

func startPacketForward() {
	for packet := range packetChan {
		msg := WebSocketMessage{
			Type: "packet",
			Data: packet,
		}
		hub.broadcast(msg)
	}
}

//export goPacketCallback
func goPacketCallback(info *C.struct_packet_info) {
	srcIP := fmt.Sprintf("%d.%d.%d.%d",
		byte(info.src_ip>>24), 
		byte(info.src_ip>>16),
		byte(info.src_ip>>8), 
		byte(info.src_ip),
	)

	dstIP := fmt.Sprintf("%d.%d.%d.%d",
		byte(info.dst_ip>>24), 
		byte(info.dst_ip>>16),
		byte(info.dst_ip>>8), 
		byte(info.dst_ip),
	)

	packetData := map[string]interface{}{
		"src_ip":    srcIP,
		"dst_ip":    dstIP,
		"src_port":  int(info.src_port),
		"dst_port":  int(info.dst_port),
		"protocol":  protoName(info),
		"timestamp": time.Now().UnixMilli(),
	}

	select {
	case packetChan <- packetData:
	default:
	}
}

//export goDNSCallback
func goDNSCallback(domain *C.char){
	d := C.GoString(domain)

	select {
	case dnsChan <- d:
	default:
	}
}

func startDNSConsumer() {
	for d := range dnsChan {
		fmt.Println("DNS: ", d)
	}
}

func chooseInterface() string {
	C.print_possible_devices()
	var key int
	fmt.Printf("Choose iface (1: default): ")
	fmt.Scan(&key)

	cstr := C.choose_device(C.int(key))
	if cstr == nil {
		fmt.Println("Failed to get device or invalid selection")
		return "wlp4s0"
	}

	defer C.free(unsafe.Pointer(cstr))

	deviceName := C.GoString(cstr)
	fmt.Printf("You chose key %d: %s\n", key, deviceName)
	return deviceName
}

func main() {
	go startPacketForward()
	go startServer()

	iface := chooseInterface()
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	ciface := C.CString(iface)
	defer C.free(unsafe.Pointer(ciface))
	time.Sleep(100 * time.Millisecond)

	fmt.Println("Start capturing...")
	go startDNSConsumer()

	go func() {
		C.start_capture(
			ciface,
			nil,
		)
	}()


	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	close(packetChan)
	close(dnsChan)
	fmt.Println("End capturing...")
}
