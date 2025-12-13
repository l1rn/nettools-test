#include "capture.h"
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void handler(
	u_char *user,
	const struct pcap_pkthdr *h,
	const u_char *bytes
) {
	struct callback_data *data = (struct callback_data *)user;
	if(data && data ->cb){
		data->cb(h->len);
	}
}

int start_capture(const char* iface, packet_cb cb){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct callback_data *data;

	handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);
	if(!handle){
		return -1;
	}
	
	data = (struct callback_data *)malloc(sizeof(struct callback_data));
	if(!data){
		pcap_close(handle);
		return -1;
	}

	data->cb = cb;

	pcap_loop(handle, 0, handler, (u_char*)data);
	pcap_close(handle);
	return 0;
}
