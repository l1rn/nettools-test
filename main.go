package main

/*
#cgo LDFLAGS: -lpcap
#include "capture.h"
#include <stdlib.h>
#include <netinet/ip.h>

extern void goPacketCallback(struct packet_info *info);

static void packet_bridge(struct packet_info *info){
	goPacketCallback(info);
}
*/
import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

func protoName(info *C.struct_packet_info) string{
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
		if info.dst_port == 443 || info.src_port == 443{
			return "QUIC"
		}
		return "UDP"
	}
	return "UNKNOWN"
}

//export goPacketCallback
func goPacketCallback(info *C.struct_packet_info){
	fmt.Println(protoName(info))
	fmt.Printf(
		"%d -> %d\n",
		int(info.src_port),
		int(info.dst_port),
	)
}

func chooseInterface() string {
	C.print_possible_devices()
	var key int;
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

func main(){
	iface := chooseInterface()
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	ciface := C.CString(iface)
	defer C.free(unsafe.Pointer(ciface))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Start capturing...")
	go func() {
		C.start_capture(
			ciface,
			(C.packet_cb)(C.goPacketCallback),
		)	
	}()

	<-sigChan

	fmt.Println("End capturing...")
}
