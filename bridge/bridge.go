package bridge

/*
#include "bridge.h"
*/
import "C"
import "fmt"

var dnsChan = make(chan string, 1000)

func GetPacketBridgeAddr() unsafe.Pointer {
    // This isn't strictly needed if we handle it in main, but it keeps things clean
    return unsafe.Pointer(C.packet_bridge)
}
