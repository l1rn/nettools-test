#include "dns.h"
#include "bridge.h"

#include <stdint.h>
#include <string.h>

static void parse_dns_name(
	const unsigned char *dns,
	int dns_len,
	char *out, 
	int out_len
	) {
	int i = 0;
	int pos = 0;

	while (pos < dns_len){
		uint8_t len = dns[pos++];
		if(len == 0) break;

		if(len > 63 || pos + len > dns_len)
			return ;
		
		if(i && i < out_len - 1)
			out[i++] = '.';
		
		for(int j = 0; j < len && i < out_len - 1; j++)
			out[i++] = dns[pos++];

		if(i >= out_len - 1)
			break;
	}
	out[i] = '\0';
}

void parse_dns(const unsigned char *data, int len){
	if(len < 12) 
		return;

	char domain[256] = {0};

	parse_dns_name(data + 12, len - 12, domain, sizeof(domain));
	if(domain[0]) {
		dns_bridge(domain);
	}
}
