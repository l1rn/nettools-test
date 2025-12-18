#include "bridge.h"

extern void goPacketCallback(struct packet_info *info);
extern void goDNSCallback(const char *domain);

void packet_bridge(struct packet_info *info){
	goPacketCallback(info);
}

void dns_bridge(const char *domain){
	goDNSCallback(domain);
}
