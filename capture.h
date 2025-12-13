#ifndef CAPTURE_H
#define CAPTURE_H

typedef struct pcap_pkthdr pcap_pkthdr_t;
typedef void (*packet_cb)(int len);

struct callback_data {
	packet_cb cb;
};

void handler(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *bytes);
int start_capture(const char* iface, packet_cb cb);

#endif
