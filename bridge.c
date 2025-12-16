#include "bridge.h"

extern void goPacketCallback(struct packet_info *info);

void packet_bridge(struct packet_info *info){
	goPacketCallback(info);
}
