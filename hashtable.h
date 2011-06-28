#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>


#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>

#include <string.h>
#include <pcre.h>

#define GET_TYPE 0
#define POST_TYPE 1
#define HEAD_TYPE 2
#define UNKNOWN_TYPE 3
#define RESPONSE_TYPE 3

#define MSG_TYPE 4


// One TCP packet
struct data_chunk
{
  uint8_t *data;		// Packet data
  int datalen;
  unsigned long seq;

  u_int32_t raw_seq;
  u_int32_t raw_ack;

  struct data_chunk *next;	// Pointer towards next packet
};


// Structure for all the HTTP data reordering
struct tcp_stream
{
  u_int32_t ip_source;		// Source IP
  u_int16_t port_source;	// Source port
  u_int32_t ip_dest;		// Destination IP
  u_int16_t port_dest;		// Destination port

  time_t time_last_packet;	// Time last packet was seen

  struct data_chunk *first_chunk;	// First data chunk (where there is GET or POST for http)
};

// Chained list of data_port_tracker elements
struct data_tracker
{
  struct tcp_stream *stream;	// First element
  struct data_tracker *previous;
  struct data_tracker *next;
};

struct Tracker
{
  struct data_tracker *first_tracker;
};

struct http_request
{
  // Data pointer
  uint8_t *data;
  int data_length;
  
  int code;       // Response code
  int nb_packets; // Number of packets in the stream
  int complete;   // Requets is complete?

  // Stream pointer
  struct tcp_stream *stream;
  uint32_t last_seq;
  uint32_t last_ack;

  // Request type
  char type;

  // Path
  uint8_t *path;
  int path_length;

  // Headers are complete
  char headers_complete;

  // Headers (offsets)
  uint8_t **headers_offsets;
  int headers_number;

  // POST data
  uint8_t *post_content;
  int post_content_length;
  int post_content_length_headers;
};


void print_http_request_content(struct http_request *request, int data);

void free_http_request(struct http_request *request);

int get_header(struct http_request *request, uint8_t *field, int hlen, uint8_t **res);

int track_tcp_packet(struct Tracker *tracker, struct iphdr *ip_hdr, struct http_request *request);




int parse_msn_packet(uint8_t *data, int data_length, uint8_t **message, int *left);
