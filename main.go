package main

/*
#cgo LDFLAGS: -lpcap
#include "capture.h"
#include <stdlib.h>

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

//export goPacketCallback
func goPacketCallback(info *C.struct_packet_info){
	fmt.Printf(
		"TCP %d -> %d\n",
		int(info.src_port),
		int(info.dst_port),
	)
}

func main(){
	C.print_possible_devices()
	iface := "wlp4s0"

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
