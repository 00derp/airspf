#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
//#include <stdint.h>

#include <string.h>
#include <malloc.h>
#include <regex.h>
#include <getopt.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <time.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>

#define _NET_IF_H // to avoid double-includes
#define u_int uint32_t
#define u_short uint16_t
#define u_char uint8_t
#include <pcap.h>
#define uint uint32_t
#include <libnet.h>

/*
 * Context for holding program state
 * */
enum airspf_state{
	INIT,
}; 
struct airspf_ctx{
	enum airspf_state state;
	int verbosity;
	char *monitor_if;
};
typedef struct airspf_ctx airspf_ctx;

struct airspf_trace{
	int is_cracked;
};
typedef struct airspf_trace airspf_trace;

/*
 * Convenience printf for debug
 */
void eprintf(char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}
/* 
 * Convenience function which is a wrapper for printf.  Only prints if
 * log_level is less than ctx->verbosity.
 */
void printlog(airspf_ctx *ctx, int log_level, char *format, ...){
  va_list ap;

  if(ctx->verbosity >= log_level){
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
  }
}


airspf_trace *match_trace(const struct pcap_pkthdr *pkthdr,
	const u_char *packet_data)
{
	return NULL;
}

/*
 * Play spoof on the packet
 * */
void play_spoof(airspf_trace* trace, const struct pcap_pkthdr *pkthdr, 
	const u_char *packet_data)
{
}

/*
 * Collect and crack the packet.
 * Indicate is_cracked 
 * */
void collect(airspf_trace* trace, const struct pcap_pkthdr *pkthdr, 
	const u_char *packet_data)
{
}

/*
 * response to client and AP
 * */
void response(airspf_trace* trace, const struct pcap_pkthdr *pkthdr, 
	const u_char *packet_data)
{
}

/*
 * Convenience function to extract the ssid name from a raw 802.11 frame
 * and copy it to the ssid_name argument.  max_name_len is the length of
 * the ssid_name buffer
 */
int get_ssid(const u_char *packet_data, char *ssid_name, u_short max_name_len){
  if(packet_data[36] == 0){ // this is the SSID
    u_short ssid_len = packet_data[37];

    if(ssid_len == 0){
      ssid_name[0] = 0;

      return 0;
    }

    u_short max_len = (u_short)(ssid_len > max_name_len ? max_name_len - 1 : ssid_len);

    memcpy(ssid_name, &packet_data[38], max_len);

    ssid_name[max_len] = 0;

    return 0;
  }

  return -1;
}

void pckt_callback(u_char *user, const struct pcap_pkthdr *pkthdr, 
	const u_char *packet_data)
{
	airspf_ctx *ctx = (airspf_ctx *)user;
	airspf_trace *trace;
	char ssid_name[256];
	uint32_t packetlen;

	packetlen = pkthdr->len;

	// code to handle skipping past "prism monitoring header" blocks
	if(*((unsigned int*)packet_data) == htonl(0x44000000)){
		uint32_t len = *((uint32_t*)(packet_data+4));
		packet_data = packet_data + len;
		packetlen -= len;
	}

	// same for radiotap headers, which have a first 16 bits of 0x0000
	if(*((uint16_t*)packet_data) == htons(0x0000)) {
		uint16_t len = *((uint16_t*)(packet_data+2));
		packet_data = packet_data + len;
		packetlen -= len;
	}

	switch(packet_data[0]){
		// data packet
		case 0x08:
			trace = match_trace(pkthdr, packet_data);
			if(trace->is_cracked)
				play_spoof(trace, pkthdr, packet_data);
			else
				collect(trace, pkthdr, packet_data);
			response(trace, pkthdr, packet_data);
			break;
		case 0x80:
			get_ssid(packet_data, ssid_name, sizeof(ssid_name));
			printlog(ctx, 4, "  beacon frame (%s)\n", ssid_name);
			break;
		case 0x40:
			get_ssid(packet_data, ssid_name, sizeof(ssid_name));
			printlog(ctx, 4, "  probe request (%s)\n", ssid_name);
			break;
		case 0x50:
			get_ssid(packet_data, ssid_name, sizeof(ssid_name));
			printlog(ctx, 4, "  probe response (%s)\n", ssid_name);
			break;
		case 0xd4:
			printlog(ctx, 4, "  acknowledgement\n");
			break;
		case 0x48:
			printlog(ctx, 4, "  null function\n");
			break;
		case 0xb0:
			printlog(ctx, 4, "  authentication\n");
			break;
		case 0xc0:
			printlog(ctx, 4, "  deauthentication\n");
			break;
		case 0x30:
			printlog(ctx, 4, "  reassociation response\n");
			break;
		case 0xc4:
			printlog(ctx, 4, "  clear to send\n");
			break;
		default:
			printlog(ctx, 5, " ***  unknown type %x\n", packet_data[0]);
	}
}

void pcap_monitor(char *interface, airspf_ctx *ctx)
{
	pcap_t *pctx;
	for(;;){
		pcap_loop(pctx, 1, pckt_callback, (u_char*)ctx);
	}
}


int main(int argc, char **argv)
{
	airspf_ctx *ctx = calloc(1, sizeof(airspf_ctx));
	pcap_monitor(ctx->monitor_if, ctx);
	
	return 0;
}
