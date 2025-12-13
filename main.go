package main

/*
#cgo LDFLAGS: -lpcap
#include "capture.h"
#include <stdlib.h>

extern void goPacketCallback(int len);

static void packet_bridge(int len){
	goPacketCallback(len);
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
func goPacketCallback(len C.int){
	fmt.Println("packet length: ", int(len))
}

func main(){
	iface := "eth0"

	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	ciface := C.CString(iface)
	defer C.free(unsafe.Pointer(ciface))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		C.start_capture(
			ciface,
			(C.packet_cb)(C.goPacketCallback),
		)	
	}()

	<-sigChan
}
