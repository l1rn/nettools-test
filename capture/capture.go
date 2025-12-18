package capture

/*
#cgo LDFLAGS: -lpcap
#include "capture.h"
#include <stdlib.h>
#include <netinet/ip.h>
*/
import "C"
import (
	"fmt"
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

func ChooseInterface() string {
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

func Start (iface string, pcb C.packet_cb, dcb C.dnc_cb) {
	cIface := C.CString(iface)
	defer C.free(unsafe.Pointer(&cIface))
	C.start_capture(cIface, pcb, dcb)
}