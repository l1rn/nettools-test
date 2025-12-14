#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>

typedef struct pcap_pkthdr pcap_pkthdr_t;

struct packet_info {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  proto;
};

typedef void (*packet_cb)(struct packet_info *info);

struct callback_data {
	packet_cb cb;
};

void handler(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *bytes);
int start_capture(const char* iface, packet_cb cb);

#endif
