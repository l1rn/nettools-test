#ifndef BRIDGE_H
#define BRIDGE_H

#include "capture.h"

void packet_bridge(struct packet_info *info);
void dns_bridge(const char *domain);

#endif // BRIDGE_H
