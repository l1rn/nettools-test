package capture

/*
#cgo LDFLAGS: -lpcap
#include "capture.h"
#include <stdlib.h>
#include <netinet/ip.h>
extern void goPacketCallback(struct packet_info*);

static void packet_bridge(struct packet_info *info) {
    goPacketCallback(info);
}
*/
import "C"
import (
	"fmt"
	"net"
	"unsafe"
)

type Packet struct {
	SrcIP 	string
	DstIP 	string
	SrcPort int
	DstPort int
	Proto 	string
	SNI 	string
}

var packetHandler func(Packet)

//export goPacketCallback
func goPacketCallback(info *C.struct_packet_info) {
	p := Packet{
		SrcIP:   ipToString(info.src_ip),
		DstIP:   ipToString(info.dst_ip),
		SrcPort: int(info.src_port),
		DstPort: int(info.dst_port),
		Proto:   protoName(info),
		SNI:     C.GoString(&info.sni[0]),
	}

	fmt.Printf("[%s]: %s:%d -> %s:%d \n", p.Proto, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)

	if packetHandler != nil {
		packetHandler(p)
	}
}

func ipToString(ip C.uint32_t) string {
	b := []byte{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	}
	return net.IP(b).String()
}

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

func Start (iface string, handler func(Packet)) {
	cIface := C.CString(iface)
	defer C.free(unsafe.Pointer(&cIface))
	C.start_capture(
		cIface,
		(C.packet_cb_t)(C.goPacketCallback), 
		nil,
	)
}