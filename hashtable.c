#include "hashtable.h"


/**
 * Initializes a http_request instance
 **/
void initialize_http_request(struct http_request *request)
{
  request->type = UNKNOWN_TYPE;
  request->path_length = 0;
  request->post_content_length = -1;
  request->post_content_length_headers = -1;
  request->headers_complete = 0;
  request-> headers_offsets = 0;
  request->headers_number = 0;
  request->data = 0;
  request->data_length = 0;
  request->stream = 0;
  request->code = 0;
  request->complete = 0;
  request->nb_packets = 0;
  request->last_seq = 0;
  request->last_ack = 0;
}


/**
 * Frees a http_request instance
 **/
void free_http_request(struct http_request *request)
{
  if (request->data != 0)
    free(request->data);

  if (request->headers_offsets != 0)
    free(request->headers_offsets);

  //free(request);
}


/**
 * Prints the content of a HTTP request instance
 **/
void print_http_request_content(struct http_request *request, int data)
{
  int i;
  uint8_t *offset;
  int response = 0;
  
  if (request->type == RESPONSE_TYPE)
    printf("######### HTTP RESPONSE CONTENT #########\n");
  else if (request->type == GET_TYPE)
    printf("######### HTTP GET CONTENT #########\n");
  else if (request->type == POST_TYPE)
    printf("######### HTTP POST CONTENT #########\n");
  else if (request->type == HEAD_TYPE)
    printf("######### HTTP HEAD CONTENT #########\n");
  else if (request->type == UNKNOWN_TYPE)
    printf("######### HTTP UNKNOWN CONTENT #########\n");

  if (request->headers_complete == 0)
    printf("Headers are incomplete\n");
  else
    printf("Headers are complete\n");

  if (request->type == RESPONSE_TYPE)
  {
    printf("Code : %d\n", request->code);
  }
  else
  {
    printf("Request path is %.*s\n", request->path_length, request->path);
  }
  
  for (i=0; i<request->headers_number; ++i)
  {
    printf("(%d-%d)\t[%.*s] -> %.*s\n", request->headers_offsets[4*i+1]-request->headers_offsets[4*i], request->headers_offsets[4*i+3]-request->headers_offsets[4*i+2], request->headers_offsets[4*i+1]-request->headers_offsets[4*i], request->headers_offsets[4*i], request->headers_offsets[4*i+3]-request->headers_offsets[4*i+2], request->headers_offsets[4*i+2]);
  }
  
  if (request->post_content_length > 0)
  {
    printf("DATA [%d] len= %d ", request->post_content_length_headers, request->post_content_length);
    if (request->post_content_length == request->post_content_length_headers)
      printf("(OK) : ");
    else
      printf("(NOK) : ");

    if (data == 1)
      printf("%.*s\n", request->post_content_length, request->post_content);
    printf("\n");
  }

  printf("########################################\n");
}


/**
 * Get the content corresponding to a field if it exists in HTTP request headers
 * Returns -1 if header is not present in request, else returns its content's length
 **/
int get_header(struct http_request *request, uint8_t *field, int hlen, uint8_t **res)
{
  int i;
  uint8_t *deb;
  uint8_t *end;
  for (i = 0; i < request->headers_number; ++i)
  {
    deb = request->headers_offsets[4*i];
    end = request->headers_offsets[4*i + 1];

    if ((hlen == end - deb) && (strncasecmp(deb, field, hlen) == 0))
    {
      *res = request->headers_offsets[4*i + 2];
      //printf("Header found: %.*s\n", request->headers_offsets[4*i + 3] - request->headers_offsets[4*i + 2], *res);
      return request->headers_offsets[4*i + 3] - request->headers_offsets[4*i + 2];
    }
  }
  
  //printf("Header not found\n");
  return -1;
}


/**
 * Parse HTTP data and fills http request structure
 * /!\ ATTENTION /!\
 * The strings inside rely on the data, so request is freed when data is
 * Only headers_offsets has to be freed
 * returns 0 if request is not complete, 1 if it is
 **/
int parse_http_data(uint8_t *data, int data_length, struct http_request *request)
{
  uint8_t get[5] = "GET ";
  uint8_t post[6] = "POST ";
  uint8_t head[6] = "HEAD ";
  uint8_t *deb;
  uint8_t *end; 

  // Puts strings info into request
  request->data = data;
  request->data_length = data_length;

  // Checks if packet starts with GET, POST or HEAD
  if ((data_length > 4) && (memcmp(data, get, 4) == 0))
  {
    request->type = GET_TYPE;
    data += 4;
    data_length -= 4;
  }
  else if ((data_length > 5) && (memcmp(data, post, 5) == 0))
  {
    request->type = POST_TYPE;
    data += 5;
    data_length -= 5;
  }
  else if ((data_length > 5) && (memcmp(data, head, 5) == 0))
  {
    request->type = HEAD_TYPE;
    data += 5;
    data_length -= 5;
  }
  else
  {
    return 0;
  }

  // Path is until we see ' '
  deb = data;
  while ((data_length > 1) && (data[0] != ' '))
  {
    data++;
    data_length--;
  }
  if (data[0] != ' ')
  {
    return 0;
  }
  request->path = deb;
  request->path_length = data - deb;
  data += 1;
  data_length -= 1;
  
  // Now HTTP version until we see \r\n
  while ((data_length > 2) && ((data[0] != '\r') || (data[1] != '\n')))
  {
    data++;
    data_length--;
  }
  if ((data[0] != '\r') && (data[1] != '\n'))
  {
    return 0;
  }
  data += 2;
  data_length -= 2;
  
  // Allocate headers offsets array
  uint8_t **headers_offsets = (uint8_t **) malloc(sizeof(uint8_t *) * 256);
  request->headers_offsets = headers_offsets;
  request->headers_number = 0;
  uint8_t **offsets = headers_offsets;

  uint8_t content_length_str[15] = "Content-Length";
  uint8_t *deb1;
  
  // Now data is like [Header1] : [Header_Content1]\r\n[Header2] : [Header_Content2]\r\n etc..
  for ( ; ; )
  {
    // If \r\n => end of headers
    if ((data_length >= 2) && (data[0] == '\r') && (data[1] == '\n'))
    {
      request->headers_complete = 1;
      break;
    }
    
    // Get Header
    deb = data;
    while ((data_length > 0) && (data[0] != ':'))
    {
      data++;
      data_length--;
    }
    if (data_length == 0)
    {
      return 0;
    }
    end = data;
    *offsets = deb;
    offsets ++;
    *offsets = end;
    offsets ++;
    
    // Get Header content
    data += 2; // ': '
    data_length -= 2;
    deb1 = data;
    while ((data_length > 2) && ((data[0] != '\r') || (data[1] != '\n')))
    {
      data++;
      data_length--;
    }
    if ((data[0] != '\r') && (data[1] != '\n'))
    {
      return 0;
    }
    *offsets = deb1;
    offsets++;
    *offsets = data;
    offsets++;
    request->headers_number++;

    // Check if header was Content-Length
    if ((end-deb == 14) && (memcmp(deb, content_length_str, 14) == 0))
    {
      //printf("Content-Length header detected!\n");
      // Convert 
      if (sscanf(deb1,"%i\r",&(request->post_content_length_headers)) !=1 )
      {
        printf("Conversion into integer of string %.*s failed\n", end-deb+1, deb);
      }
      //else
      //  printf("Content-Length = %d\n", request->post_content_length_headers);
    }

    data += 2; // '\r\n'
    data_length -= 2;
  }

  // Now is the POST data
  data += 2; // '\r\n'
  data_length -= 2;

  request->post_content_length = data_length;
  request->post_content = data;

  // If request is a GET, the request is complete
  if (request->type == GET_TYPE)
  {
  if (data_length == 0)
  {
    request->complete = 1;
    return 1;
  }
  else
    // Some data remains even though this a GET request... Weird :)
    return 0;
  }
  // If request is a POST, data length has to match the length specified in headers
  else if (request->type == POST_TYPE)
  {
  // If it remains the same amount of data that mentioned in the Content-Length field, then request is complete
    if (data_length == request->post_content_length_headers)
    {
      request->complete = 1;
      return 1;
    }
    else
      return 0;
  }
  else if (request->type == HEAD_TYPE)
  {
  if (data_length == 0)
    {
      request->complete = 1;
      return 1;
    }
  else
    // Some data remains even though this a HEAD request... Weird :)
    return 0;
  }
}


/**
 * Parse HTTP data and fills http request structure
 * /!\ ATTENTION /!\
 * The strings inside rely on the data, so request is freed when data is
 * Only headers_offsets has to be freed
 * returns 0 if request is not complete, 1 if it is
 **/
int parse_http_data_response(uint8_t *data, int data_length, struct http_request *request)
{
  uint8_t http[5] = "HTTP";
  uint8_t *deb;
  uint8_t *end; 

  // Puts strings info into request
  request->data = data;
  request->data_length = data_length;

  // Checks if packet starts with HTTP
  if ((data_length > 4) && (memcmp(data, http, 4) == 0))
  {
    data += 4;
    data_length -= 4;
    request->type = RESPONSE_TYPE;
  }
  else
  {
    return 0;
  }

  // Code starts after ' '
  while ((data_length > 1) && (data[0] != ' '))
  {
    data++;
    data_length--;
  }
  if (data[0] != ' ')
  {
    return 0;
  }
  data += 1;
  data_length -= 1;
  
  // Code is until we see ' '
  deb = data;
  while ((data_length > 1) && (data[0] != ' '))
  {
    data++;
    data_length--;
  }
  if (data[0] != ' ')
  {
    return 0;
  }
  if (sscanf(deb,"%i ",&(request->code)) !=1 )
  {
    printf("Conversion into integer of string %.*s failed\n", end-deb+1, deb);
    return 0;
  }
  data += 1;
  data_length -= 1;

  // OK is until we see \r\n
  while ((data_length > 2) && ((data[0] != '\r') || (data[1] != '\n')))
  {
    data++;
    data_length--;
  }
  if ((data[0] != '\r') && (data[1] != '\n'))
  {
    return 0;
  }
  data += 2;
  data_length -= 2;
  
  // Allocate headers offsets array
  uint8_t **headers_offsets = (uint8_t **) malloc(sizeof(uint8_t *) * 256);
  request->headers_offsets = headers_offsets;
  request->headers_number = 0;
  uint8_t **offsets = headers_offsets;

  uint8_t content_length_str[15] = "Content-Length";
  uint8_t *deb1;
  
  // Now data is like [Header1] : [Header_Content1]\r\n[Header2] : [Header_Content2]\r\n etc..
  for ( ; ; )
  {
    // If \r\n => end of headers
    if ((data_length >= 2) && (data[0] == '\r') && (data[1] == '\n'))
    {
      request->headers_complete = 1;
      break;
    }
    
    // Get Header
    deb = data;
    while ((data_length > 0) && (data[0] != ':'))
    {
      data++;
      data_length--;
    }
    if (data_length == 0)
    {
      return 0;
    }
    end = data;
    *offsets = deb;
    offsets ++;
    *offsets = end;
    offsets ++;
    
    // Get Header content
    data += 2; // ': '
    data_length -= 2;
    deb1 = data;
    while ((data_length > 2) && ((data[0] != '\r') || (data[1] != '\n')))
    {
      data++;
      data_length--;
    }
    if ((data[0] != '\r') && (data[1] != '\n'))
    {
      return 0;
    }
    *offsets = deb1;
    offsets++;
    *offsets = data;
    offsets++;
    request->headers_number++;

    // Check if header was Content-Length
    if ((end-deb == 14) && (memcmp(deb, content_length_str, 14) == 0))
    {
      //printf("Content-Length header detected!\n");
      // Convert 
      if (sscanf(deb1,"%i\r",&(request->post_content_length_headers)) !=1 )
      {
        printf("Conversion into integer of string %.*s failed\n", end-deb+1, deb);
      }
      //else
      //  printf("Content-Length = %d\n", request->post_content_length_headers);
    }

    data += 2; // '\r\n'
    data_length -= 2;
  }

  // Now is the POST data
  data += 2; // '\r\n'
  data_length -= 2;

  request->post_content_length = data_length;
  request->post_content = data;

  // If it remains the same amount of data that mentioned in the Content-Length field, then request is complete
  if (data_length == request->post_content_length_headers)
  {
    request->complete = 1;
    return 1;
  }
  // If Content-Length is not specified, let's assume stream is complete
  else if (request->post_content_length_headers == -1)
  {
    request->complete = 1;
    return 1;
  }
  else
    return 0;
}


/**
 * Prints one tracker content
 **/
 void print_tracker_content(struct data_tracker *tracker)
 {
  struct tcp_stream *stream = tracker->stream;
  struct data_chunk *chunk = stream->first_chunk;
  
  printf("Tracker [%x] : %d -> %d\n", tracker, stream->port_source, stream->port_dest);
  
  int nb = 0;
  
  while (1)
  {
    if (chunk == NULL)
    {
      break;
    }

    nb++;
    //printf("\tChunk %d : SEQ = %d\n", nb, chunk->seq);

    chunk = chunk->next;
  }
  printf("\t%d chunks\n", nb);
}


/**
 * Prints all trackers content
 **/
void print_main_tracker_content(struct Tracker *main_tracker)
{
  struct data_tracker *tracker = main_tracker->first_tracker;
  printf("\n######### Main tracker content #########\n");
  
  // Loop over all the trackers
  while (1)
  {
    if (tracker == NULL)
    {
      break;
    }
    
    // Print tracker content
    print_tracker_content(tracker);
    
    if (tracker == tracker->next)
    {
      print_tracker_content(tracker->next);
      printf("!!!!!!!!!!!!!!!!!!! INFINITE LOOP !!!!!!!!!!!!!!!!!!!!!\n");
      exit(1);
    }
    tracker = tracker->next;
  }
  
  printf("########################################\n\n");
  return;
}


/**
 * Removes the tracker from the chained list and frees its content
 **/
void delete_tracker(struct Tracker *main_tracker, struct data_tracker *tracker)
{
  //printf("Deleting tracker %x ...\n", tracker);
  //fflush(stdout);
  struct tcp_stream *stream = tracker->stream;
  
  //printf("Getting first chunk (stream =%x)... ", stream);
  //fflush(stdout);
  
  // Frees stream and all its chunks
  struct data_chunk *chunk = stream->first_chunk;
  
  //printf("OK\n");
  //fflush(stdout);
  
  while (1)
  {
    if (chunk == NULL)
    {
      break;
    }
    
    //printf("Freeing chunk %x SEQ = %d... ", chunk, chunk->seq);
    //fflush(stdout);
    free(chunk->data);
    free(chunk);
    //printf("OK\n");
    //fflush(stdout);
    
    chunk = chunk->next;
  }
  
  
  //printf("Freeing stream...");
  //fflush(stdout);
  free(stream);
  //printf("OK\n");
  //fflush(stdout);
  
  // Removes tracker from the chained list
  if (tracker->previous == NULL)
  {
    //printf("Tracker to be deleted is first! ");
    fflush(stdout);
    main_tracker->first_tracker = tracker->next;
    
    if (main_tracker->first_tracker != NULL)
    {
      // Removing the only tracker in trackers list
      main_tracker->first_tracker->previous = NULL;
    }
  }
  else
  {
    //printf("Tracker to be deleted is not first! ");
    //fflush(stdout);
    //printf("Previous: %x\n", tracker->previous);
    //printf("Next: %x\n", tracker->next);
    //fflush(stdout);
    
    tracker->previous->next = tracker->next;
    if (tracker->next != NULL)
    {
      tracker->next->previous = tracker->previous;
    }
  }
  
  free(tracker);
  //printf("OK\n");
  
  //print_main_tracker_content(main_tracker);
}

/**
 * Gets time in microseconds
 **/
long int clock1()
{
  struct timeval tv;
  struct timezone tz;
  gettimeofday(&tv, &tz);
  return tv.tv_usec;
}
 
/**
 * Checks if packet is complete
 **/
// int is_packet_full(uint8_t *data, int datalen)
// { 
//   long int deb = clock1();
// 
//   uint8_t get[5] = "GET ";
//   uint8_t post[6] = "POST ";
//   uint8_t end[5] = "\r\n\r\n";
//   uint8_t content_length[17] = "Content-Length: ";
// 
//   // Checks if packet starts with GET or POST
//   if (memcmp(data, get, 4) == 0)
//   {
//     printf(" -- GET au debut\n");
//     // Packet is a GET request
//     // To be complete it must end with \r\n\r\n
//     if (memcmp(data + datalen - 4, end, 4) == 0)
//       return 1;
//     else
//       return 0;
//   }
// 
//   if (memcmp(data, post, 5) != 0)
//   {
//     printf(" -- ni GET ni POST au debut\n");
//     // Packet is neither a GET or POST request : it is not complete
//     return 0;
//   }
// 
//   printf(" -- POST au debut\n");
//   //printf("datalen = %d\n", datalen);
// 
//   // Packet is a POST request
//   int ovector[30];
//   const char *errptr;
//   int c;
//   char *post_regexp = "Content-Length: ([0-9]*)\r\n(.*?)\r\n\r\n(.)";
//   pcre *match_post = pcre_compile(post_regexp, PCRE_DOTALL, &errptr, &c, NULL);
//   if(match_post == NULL)
//   {
//     printf("Error at character %d in pattern: \"%s\" (%s)\n", c, post_regexp, errptr);
//   }
//   else
//   {
//     if(pcre_exec(match_post, NULL, data, datalen, 0, 0, ovector, 30) > 0)
//     {
//       int post_content_length_length = ovector[3]-ovector[2];
//       int post_content_length = datalen-ovector[6];
// 
//       char len_str[8];
//       sprintf(len_str, "%.*s", post_content_length_length, data + ovector[2]);
// 
//       int length;
//       if (sscanf(len_str,"%i",&length) !=1 )
//       {
//         printf("Problème de conversion de %s en entier\n", len_str);
//         return 0;
//       }
// 
//       printf("Content-Length : %d - Post : %d\n", length, post_content_length);
//       printf("Time for is_stream_full: %d\n", clock1() - deb);
// 
//       if (length == post_content_length)
//         return 1;
//       else
//         return 0;
//     }
//     else
//     {
//       printf("No match with content-length and end of headers...\n");
//       return 0;
//     }
//   }
// 
// }


/**
 * Converts 4 bytes in little endian to an unsigned long in big indian
 **/
unsigned long u_int32_t_to_ul(u_int32_t u32)
{
  u_int8_t *first = (u_int8_t *) (&u32);

  unsigned long ul = 0;
  ul |= (first[0] << 24);
  ul |= (first[1] << 16);
  ul |= (first[2] << 8);
  ul |= first[3];

  return ul;
}


/**
 * Checks if stream is complete (and concatenates all stream packets)
 **/
int is_stream_full(struct tcp_stream *stream, uint8_t ** full_packet, struct http_request *request, int response)
{
  // Concatenates all the packets in stream
  // 1- calculate total size
  int total_length = 0;
  int i = 0;
  struct data_chunk *chunk = stream->first_chunk;
  while (1)
  {
    if (chunk == NULL)
      break;
  total_length += chunk->datalen;
  chunk = chunk->next;
  ++i;
  }
  printf("%d packets in stream, total length : %d\n", i, total_length);

  // 2- Allocates big string
  uint8_t *packet = (uint8_t *) malloc(total_length * sizeof(uint8_t));

  // 3- Concatenates string
  uint8_t *dest = packet;
  chunk = stream->first_chunk;
  while (1)
  {
    if (chunk == NULL)
      break;
    
    //printf("Concatenating...\n");
    memcpy(dest, chunk->data, chunk->datalen);
    request->nb_packets++;
    
//     printf("DATA STRING: \n");
//     int i;
//     for (i=0; i<chunk->datalen; ++i)
//       printf("%c", chunk->data[i]);
//     printf("\n");
//     printf("FIN DATA STRING\n");
  
    dest += chunk->datalen;
    chunk = chunk->next;
  }
  
//   printf("REASSEMBLED PACKET:\n");
//   int i;
//   for (i=0; i<total_length; ++i)
//     printf("%c", packet[i]);
//   printf("\n");
//   printf("FIN REASSEMBLED\n");

  // 4- Check if packet is valid

  //printf("\n\nTEST CUSTOM HTTP PARSING... :)\n");
  
  
  long int deb = clock1();
  request->stream = stream;
  int rec;
   
   if (response == 0)
    rec = parse_http_data(packet, total_length, request);
  else
    rec = parse_http_data_response(packet, total_length, request);
  //printf("Time for parse_http_data: %d\n", clock1() - deb);

  if (rec == 0)
    printf("Request incomplete\n");
  else if (rec == 1)
    printf("Request complete\n");
  //print_http_request_content(request, 0);
  return rec;

//   //Old HTTP parsing
//   int rc = is_packet_full(packet, total_length);
//   if (rc == 1)
//   {
//     *full_packet = packet;
//     return total_length;
//   }
//   else
//   {
//     free(packet);
//     return 0;
//   }
}


/**
 * We have received a TCP packet and we would like to reorder the HTTP packet
 * If the TCP packet is complete, we return it, otherwise we store it with other  packets from the same stream
 **/
int track_tcp_packet(struct Tracker *tracker, struct iphdr *ip_hdr, struct http_request *request)
{
  struct data_tracker *first = tracker->first_tracker;

  // Extract TCP data
  struct tcphdr *tcp_hdr = (struct tcphdr*) ((const uint8_t *) ip_hdr + (ip_hdr->ihl * 4));
  uint8_t *data = (uint8_t*)tcp_hdr + tcp_hdr->doff * 4;
  uint16_t datalen = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - (tcp_hdr->doff * 4);

  uint8_t *data_copy = (uint8_t *) malloc(datalen * sizeof(uint8_t));
  memcpy(data_copy, data, datalen);
  data = data_copy;

  // First, extract IPs, ports and seq
  u_int32_t ip_source = ip_hdr->saddr;			// Source IP
  u_int16_t port_source = ntohs(tcp_hdr->source);	// Source port
  u_int32_t ip_dest = ip_hdr->daddr;			// destination IP
  u_int16_t port_dest = ntohs(tcp_hdr->dest);		// Dest port	
  unsigned long seq = u_int32_t_to_ul(tcp_hdr->seq);	// Sequence number
  
  int response = 0;
  if (port_source == 80)
    response = 1;

  printf("\nNew TCP packet arrived (SEQ =  %u %02x %02x %02x %02x)\n", seq, *((u_int8_t *) &(tcp_hdr->seq)), *((u_int8_t *) &(tcp_hdr->seq) + 1), *((u_int8_t *) &(tcp_hdr->seq) + 2), *((u_int8_t *) &(tcp_hdr->seq) + 3));

  // Check if packet is full
  /* ???? Is it really useful ???? Why not inserting it and checking after ????*/
  initialize_http_request(request);
  request->nb_packets = 1;
  if (response == 0)
  {
    if (parse_http_data(data, datalen, request))
    {
      //print_http_request_content(request, 0);
      printf("Packet is complete :) No need to track!\n");
      return 1;
    }
      else
    {
      printf("Packet is incomplete. Let's insert it in the tracker...\n");
    }
  }
  else
  {
    if (parse_http_data_response(data, datalen, request))
    {
      //print_http_request_content(request, 0);
      printf("Packet is complete :) No need to track!\n");
      return 1;
    }
      else
    {
      printf("Packet is incomplete. Let's insert it in the tracker...\n");
    }
  }

  initialize_http_request(request);

  // Packet is not complete => insert packet in tracker
  // Create new chunk structure
  //printf("Creating new chunk... ");
  //fflush( stdout );
  struct data_chunk *new_chunk = (struct data_chunk *) malloc(sizeof(struct data_chunk));
  new_chunk->data = data;
  new_chunk->datalen = datalen;
  new_chunk->seq = seq;
  new_chunk->next = NULL;
  //printf("OK\n");

  char part_of_stream = 1;

  // Browse data tracker to see if the packet is part of a stream already tracked
  struct tcp_stream *current_stream;
  struct tcp_stream *previous_stream = 0;
  struct data_tracker *current_tracker = first;
  while (1)
  {
    if (current_tracker == NULL)
    {
      // End of tracker
      part_of_stream = 0;
      //printf("Last tracker\n");
      fflush( stdout );
      break;
    }
    else
    {
      // Get stream
      //printf("Getting stream... ");
      //fflush( stdout );
      current_stream = current_tracker->stream;
      //printf("OK stream = %x tracker = %x\n", current_stream, current_tracker);
      //fflush( stdout );

      // Check if the packet is part of this stream
      if ((ip_source == current_stream->ip_source) && (port_dest == current_stream->port_dest) && (ip_dest == current_stream->ip_dest) && (port_source == current_stream->port_source))
      {
        printf("Stream was already tracked!\n");
        fflush( stdout );

        // Current stream is tracking this packet
        // Let's insert it in the tracked stream
        //printf("Getting first chunk... ");
        //fflush( stdout );
        struct data_chunk *current_chunk = current_stream->first_chunk;
        //printf("OK\n");
        //fflush( stdout );

        if (seq < current_chunk->seq)
        {
          // Let us insert chunk at the beginning of the stream
          //printf("Inserting at the beginning... ");
          //fflush( stdout );
          current_stream->first_chunk = new_chunk;
          new_chunk->next = current_chunk;
          //printf("OK\n");
          //fflush( stdout );
          break;
        }
        else if (seq > current_chunk->seq)
        {
          //printf("Browsing chunks... (%x < %x))\n", current_chunk->seq, seq);
          //fflush( stdout );
          while (1)
          {
            //printf("Next chunk address: %x\n", current_chunk->next);
            //fflush( stdout );

            if (current_chunk->next == NULL)
            {
              // Let's insert the packet at the end (most frequent case)
              //printf("Inserting at the end... ");
              //fflush( stdout );
              current_chunk->next = new_chunk;
              //printf("OK\n");
              //fflush( stdout );
              break;
            }
            else if (seq < current_chunk->next->seq)
            {
              // Let's insert the packet between the current chunk and the next one
              //printf("Inserting in the middle... (%x < %x) ", seq, current_chunk->next->seq);
              //fflush( stdout );
              new_chunk->next = current_chunk->next;
              current_chunk->next = new_chunk;
              //printf("OK\n");
              //fflush( stdout );
              break;
            }
            else if (seq == current_chunk->next->seq)
            {
              //printf("We have this packet already...\n");
              fflush( stdout );
              // We already had this packet
              return 0;
            }
            else if (seq > current_chunk->next->seq)
            {
              //printf("Moving to next chunk (%x < %x) \n", current_chunk->next->seq, seq);
              //fflush( stdout );
              current_chunk = current_chunk->next;
            }
          }
          break;
        }
        else
          // We already had this packet
          {
          //printf("We already have this packet (first) in tracker...\n");
          fflush(stdout);
          return 0;
          }
      }

      // Let's check next stream
      else
      {
        // If the last packet in this stream is too old, let's stop tracking the stream
        time_t timeval = time(NULL);

        if (timeval - current_stream->time_last_packet > 10)
        {
        	// Stream is too old, so let's delete it
        	delete_tracker(tracker, current_tracker);
        	first = tracker->first_tracker;
        	//printf("Deleting OK!\n");
        	//fflush( stdout );
        }
      
        //printf("Moving to next tracker...\n");
        //fflush( stdout );
      
        current_tracker = current_tracker->next;
      
        //printf("Next tracker: %x\n", current_tracker);
        //fflush(stdout);
        }
    }

  }

  // Packet has been inserted in tracker
  if (part_of_stream == 1)
  {

//   //TEST delete tracker
//   static int ind = 0;
//   ind++;
//   if (ind == 7)
//   {
//     // Test delete tracker
//     print_main_tracker_content(tracker);
//     delete_tracker(tracker, current_tracker);
//     print_main_tracker_content(tracker);
//     exit(0);
//   }

    // Print trackers content
    //print_main_tracker_content(tracker);
  
    // Let's check if the whole stream is valid
    uint8_t *packet = NULL;

    //printf("Checking if stream is full...\n");
    //fflush(stdout);
    request->last_seq = tcp_hdr->seq;
    request->last_ack = tcp_hdr->ack_seq;
    int datalen = is_stream_full(current_stream, &packet, request, response);

    if (datalen != 0)
    {
      int i;
      
      printf(":) :) :) Packet reconstitution SUCCESSFUL!!! (: (: (:\n");
//       for (i=0; i<datalen; ++i)
//       {
//         printf("%c", packet[i]);
//       }
//       printf("\n");
      
      delete_tracker(tracker, current_tracker);
      first = tracker->first_tracker;
    }
    else
    {
      printf("Stream is still not complete\n");
    }
  }
  
  // If packet has not been yet insered in the tracker, then it is the beginning of a new stream so let's add a stream to track
  else
  {
    //printf("Adding first stream to tracker...\n");
    //fflush(stdout);
    // Insertion at the beginning of the list
    struct tcp_stream *stream = (struct tcp_stream*) malloc(sizeof(struct tcp_stream));
    if (stream == NULL)
    {
      printf("Allocation failed!\n");
      return 0;
    }

    time_t timeval = time(NULL);
    
    // Stream track information
    stream->first_chunk = new_chunk;
    stream->ip_source = ip_source;		// Source IP
    stream->port_source = port_source ;		// Source port
    stream->ip_dest = ip_dest;			// destination IP
    stream->port_dest = port_dest ;		// Dest port
    stream->time_last_packet = timeval;		// Time last packet was seen
    
    struct data_tracker *new_tracker = (struct data_tracker*) malloc(sizeof(struct data_tracker));
    new_tracker->stream = stream;
    new_tracker->next = first;
    new_tracker->previous = NULL;

    if (first == NULL)
    {
      //printf("Tracker is empty, let's set the first element\n");
    }
    else
    {
      first->previous = new_tracker;
    }
    tracker->first_tracker = new_tracker;

    //printf("### Tracker %x inserted, stream %x created ###\n", new_tracker, stream);

    // Print trackers content
    //print_main_tracker_content(tracker);
  }

  return 1;
}

	

/**
 * Parse MSN data and fills http request structure
 * Left is the message ID of the last message in the packet
 * returns the message content length
 **/
int parse_msn_packet(uint8_t *data, int data_length, uint8_t **message, int *left)
{
  int ovector[30];
  const char *errptr;
  int c;
  *left = 0;

  pcre *match_message = pcre_compile("MSG ([0-9]*) [A-Z] [0-9]*\r\n(.*?)\r\n\r\n(.*?)($|MSG )", PCRE_DOTALL, &errptr, &c, NULL);
  if(match_message == NULL)
  {
    printf("Error in pattern\n");
    return 0;
  }
  
  int first = 1;
  int len = 0;
  uint8_t *write;
  
  for ( ; ; )
  {
    if(pcre_exec(match_message, NULL, data, data_length, 0, 0, ovector, 30) > 0)
    {
      if (first == 1)
      {
        write = (uint8_t *) malloc(sizeof(uint8_t) * 2000);
        first = 0;
        *message = write;
      }
      else
      {
        write[0] = '\n';
        write ++;
        len++;
      }

      //printf("Left extracted: '%.*s'\n", ovector[3] - ovector[2] + 1, data + ovector[2]);

      if (sscanf(data + ovector[2],"%i ",left) !=1 )
      {
        printf("Conversion into integer of left %.*s failed\n", ovector[3] - ovector[2], data + ovector[2]);
      }

      //printf("LEFT = %d\n", *left);

      memcpy(write, data + ovector[6], ovector[7] - ovector[6]);
      write += ovector[7] - ovector[6];
      len += ovector[7] - ovector[6];

      data += ovector[7];
      data_length -= ovector[7];
    }
    else
    {
      return len;
    }
  }

}

