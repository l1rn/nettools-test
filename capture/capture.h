#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>

#define MAX_NAME 256

typedef struct pcap_pkthdr pcap_pkthdr_t;

struct packet_info {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  proto;
	char     sni[MAX_NAME];
};

typedef void (*packet_cb_t)(struct packet_info*);
typedef void (*dns_cb_t)(const char*);

struct callback_data {
	packet_cb_t packet_cb;
	dns_cb_t dns_cb;
};

void 	handler(
	unsigned char *user, 
	const struct pcap_pkthdr *h, 
	const unsigned char *bytes
);
int 	start_capture(
	const char* iface, 
	packet_cb_t p_cb, 
	dns_cb_t d_cb
);

void 	print_possible_devices();
char* 	choose_device(int key);
#endif
