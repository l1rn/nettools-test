#include "capture.h"

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h> 

#include <arpa/inet.h>

static packet_cb_t G_packet_cb = NULL;
static dns_cb_t G_dns_cb = NULL;

static void parse_tls_sni(
	const u_char *payload,
	int payload_len,
	struct packet_info *info
){
	info->sni[0] = '\0';

	if(payload_len < 5)
		return;

	if(payload[0] != 0x16)
		return;

	if(payload_len < 6 || payload[5] != 0x01)
		return;

	int pos = 5;
	pos += 4;
	pos += 34;

	if(pos >= payload_len) return;

	int session_len = payload[pos];
	pos += 1 + session_len;
	if(pos >= payload_len) return;

	int cipher_len = (payload[pos] << 8) | payload[pos+1];
	pos += 2 + cipher_len;
	if(pos >= payload_len) return;

	int comp_len = payload[pos];
	pos += 1 + comp_len;
	if(pos >= payload_len) return;

	int ext_len = (payload[pos] << 8) | payload[pos+1];
	pos += 2;

	int end = pos + ext_len;
	while(pos + 4 <= end && pos + 4 <= payload_len){
		uint16_t type = (payload[pos] << 8) | payload[pos+1];
		uint16_t len = (payload[pos+2] << 8) | payload[pos+3];
		pos += 4;

		if(type == 0x0000) {
			if(pos + 5 > payload_len)
				return;
			
			int name_len = (payload[pos+3] << 8) | payload[pos+4];
			if(name_len <= 0 || name_len > 255)
				return;
			
			memcpy(info->sni, payload + pos + 5, name_len);
			info->sni[name_len] = '\0';
			return;
		}

		pos += len;
	}
}

void handler(
	u_char *user,
	const struct pcap_pkthdr *h,
	const u_char *bytes
) {
	struct callback_data *data = (struct callback_data *)user;
	if(!data || !data->packet_cb) return;

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
	
	info.src_ip = ip->saddr;
	info.dst_ip = ip->daddr;
	info.proto = ip->protocol;
	if(ip->protocol == IPPROTO_TCP){
		struct tcphdr *tcp = (struct tcphdr *)(
			bytes + sizeof(struct ether_header) + ip_header_len
		);
		int tcp_header_len = tcp->doff * 4;

		info.src_port	= ntohs(tcp->source);
		info.dst_port 	= ntohs(tcp->dest);
		
		const u_char *payload = bytes 
			+ sizeof(struct ether_header)
			+ ip_header_len
			+ tcp_header_len;

		int payload_len = h->caplen - (payload - bytes);
		
		if(payload <= 0) 
			return;
		
		if(info.src_port == 443 || info.dst_port == 443){
			parse_tls_sni(payload, payload_len, &info);
		}
	}

	if(ip->protocol == IPPROTO_UDP){
		struct udphdr *udp = (struct udphdr *)(
			bytes + sizeof(struct ether_header) + ip_header_len
		);
		
		uint16_t src = ntohs(udp->source);
		uint16_t dst = ntohs(udp->dest);
		
		info.src_port 	= src;
		info.dst_port	= dst;
		
	}
	data->packet_cb(&info);
}

int start_capture(const char* iface, packet_cb_t p_cb, dns_cb_t d_cb){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct callback_data *data;

	G_packet_cb = p_cb;
	G_dns_cb = d_cb;

	handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);
	if(!handle){
		return -1;
	}
	
	data = (struct callback_data *)malloc(sizeof(struct callback_data));
	if(!data){
		pcap_close(handle);
		return -1;
	}

	data->packet_cb = p_cb;
	data->dns_cb = d_cb;

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
