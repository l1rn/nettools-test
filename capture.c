#include "capture.h"

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h> 


void handler(
	u_char *user,
	const struct pcap_pkthdr *h,
	const u_char *bytes
) {
	struct callback_data *data = (struct callback_data *)user;
	if(!data || !data->cb) return;

	if(h->caplen < sizeof(struct ether_header) + sizeof(struct iphdr))
		return;

	struct ether_header *eth = (struct ether_header *)bytes;
	if(ntohs(eth->ether_type) != ETHERTYPE_IP)
		return;

	struct iphdr *ip = (struct iphdr *)(bytes + sizeof(struct ether_header));

	if(ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
		return;

	int ip_header_len = ip->ihl * 4;
	if(ip_header_len < sizeof(struct iphdr))
		return;
	
	if(h->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr))
		return;
	
	struct packet_info info;
	
	memset(&info, 0, sizeof(info));
	
	if(ip->protocol == IPPROTO_TCP){
		struct tcphdr *tcp = (struct tcphdr *)(
			bytes + sizeof(struct ether_header) + ip_header_len
		);

		info.src_ip	= ip->saddr;
		info.dst_ip 	= ip->daddr;
		info.src_port	= ntohs(tcp->source);
		info.dst_port 	= ntohs(tcp->dest);
		info.proto 	= ip->protocol;
	}

	if(ip->protocol == IPPROTO_UDP){
		struct udphdr *udp = (struct udphdr *)(
			bytes + sizeof(struct ether_header) + ip_header_len
		);
		
		info.src_ip 	= ip->saddr;
		info.dst_ip 	= ip->daddr;
		info.src_port 	= ntohs(udp->source);
		info.dst_port	= ntohs(udp->dest);
		info.proto 	= ip->protocol;
	}

	data->cb(&info);
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

void print_possible_devices(){
	pcap_if_t *devices;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&devices, errbuf) == -1){
		fprintf(stderr, "Error to capture devices: %s\n", errbuf);
		return;
	}	

	printf("Devices: \n");
	short int i = 1;
	for(pcap_if_t *d = devices; d != NULL; d = d->next){
		printf("- [%d] %s\n", i, d->name);
		if(d->description) {
			printf("   Description: %s\n", d->description);
		}

		for(pcap_addr_t *a = d->addresses; a != NULL; a = a->next){
			if(a->addr->sa_family == AF_INET){
				char ip[INET_ADDRSTRLEN];
				inet_ntop(
					AF_INET, 
					&((struct sockaddr_in*)a->addr)->sin_addr,
					ip,
					INET_ADDRSTRLEN
				);

				printf("   IPv4: %s\n", ip);
			}
		}
		i++;
		printf("\n");
	}

	pcap_freealldevs(devices);
}

char *choose_device(int key) {
	pcap_if_t *devices;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&devices, errbuf) == -1){
		fprintf(stderr, "Error to find devices: %s\n", errbuf);
		return NULL;
	}
	short int i = 1;
	char *result = NULL;

	for(pcap_if_t *d = devices; d != NULL; d = d->next){
		if(i == key){
			result = strdup(d->name);
			break;
		}
		i++;
	}

	
	pcap_freealldevs(devices);

	if(!result){
		printf("Error: not found device by this key");
	}
	return result;
}
