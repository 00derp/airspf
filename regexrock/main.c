////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
//
#include <pcre.h>
//
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

////////////////////////////////////////////////////////////////////////////////
// HTML REQUEST
const char* regex_htmlreq_match = "^(GET|POST)";
const char* regex_htmlreq_ignore = "^GET [^ ?]+\\.(jpg|jpeg|gif|png|tif|tiff)";

const char* regex_htmlreq_handler
(const char* data, int dlen, int* odlen, int offset[])
{
  static const char*
  http_response = 
  "HTTP/1.1 200 OK\r\n"
  "Connection: close\r\n"
  "Content-Type: text/html\r\n"
  "\r\n"
  "<html><head><title>HELLO DEFCON!</title>\r\n"
  "</head><body>\r\n"
  "<blink><font size=+5 color=red>\r\n"
  "HAHAHAHA! Your Wireless Network is suffering spoofing attack!\r\n"
  "</font>\r\n"
  "</blink>\r\n"
  "<p>\r\n"
  "\r\n";
  
  *odlen = strlen(http_response);
  return http_response;
}

////////////////////////////////////////////////////////////////////////////////
// REPLACE KEYWORD
char replacement[1024];
#define MAX_MATCHES

const char* regex_replacekeyword_handler
(const char* data, int dlen, int* odlen, int offset[])
{
  
  
  
  *odlen = 4;
  return "haha";
}

////////////////////////////////////////////////////////////////////////////////

typedef const char* (*regex_listener_hanlder)
(const char* data, int dlen, int* odlen, int offset[]);

struct regex_listener{
  pcre* match;
  pcre* ignore;
  regex_listener_hanlder handler;
  
  struct regex_listener* next;
};
typedef struct regex_listener regex_listener;

regex_listener* regex_listener_list = NULL;

void regex_listener_emit(const char* data, int dlen);

void regex_listener_scan(const char* data, int dlen)
{
  int offset[30];
  int xoffset[30];
  regex_listener* rl;
  
  for(rl = regex_listener_list; rl; rl = rl->next){
    if(pcre_exec(rl->match, NULL, data, dlen, 0, 0, offset, 30)>0){
      if(rl->ignore && 
         pcre_exec(rl->ignore, NULL, data, dlen, 0, 0, xoffset, 30)>0){
        continue;
      }
      
      // Spoof a data
      int odlen;
      const char* odata = rl->handler(data, dlen, &odlen, offset);
      
      // Send data
      regex_listener_emit(odata, odlen);
      
    }
  }
}

void regex_listener_add(const char* match, const char* ignore,
                        regex_listener_hanlder handler)
{
  regex_listener* tmp = malloc(sizeof(regex_listener));
  if(!tmp){
    perror("new regex_listener");
    abort();
  }
  
  memset(tmp, 0, sizeof(regex_listener));
  
  if(!match || !handler)
    abort();
  
  const char *errptr;
  int c;
  
  tmp->match = pcre_compile(match, PCRE_MULTILINE|PCRE_DOTALL, 
                            &errptr, &c, 0);
  
  if(!tmp->match){
    printf("Error at character %d in regex: \"%s\" (%s)\n", 
           c, match, errptr);
    abort();
  }
  
  if(ignore){
    tmp->ignore = pcre_compile(ignore, PCRE_MULTILINE|PCRE_DOTALL, 
                               &errptr, &c, 0);
    
    if(!tmp->ignore){
      printf("Error at character %d in regex: \"%s\" (%s)\n", 
             c, ignore, errptr);
      abort();
    }
  }
  
  tmp->handler = handler;
  
  tmp->next = regex_listener_list;
  regex_listener_list = tmp;
}

////////////////////////////////////////////////////////////////////////////////

void regex_listener_emit(const char* data, int dlen){
  
  // Injecting Packet
  printf("%*s\n", dlen, data);
  
}

////////////////////////////////////////////////////////////////////////////////

static void _usage(void)
{
  puts("regexrock");
  puts("regexrock match replacement [ignore]");
}

int main(int argc, char* argv[])
{
  if(argc != 1 && argc != 3 && argc != 4){
    _usage();
    return 1;
  }
  
  // Initialize HTML Spoofer
  regex_listener_add(regex_htmlreq_match, regex_htmlreq_ignore, 
                     regex_htmlreq_handler);
  
  // Initialize Keyword Replacer
  if(argc >= 3){
    const char* reg_match = argv[1];
    const char* reg_replace = argv[2];
    const char* reg_ignore = argv[3];
    
    strcpy(replacement, reg_replace);
    
    regex_listener_add(reg_match, reg_ignore, regex_replacekeyword_handler);
  }
  
  //
  //
  
  // read
  int readsize = 0;
  char buffer[2048];
  while(readsize < 2048-1 && 
        fgets(buffer+readsize, 2048-readsize, stdin)){
    readsize += strlen(buffer+readsize);
  }
  
  //
  struct timeval before, after;
  gettimeofday(&before, NULL);
  
  // spoof
  regex_listener_scan(buffer, strlen(buffer));
  
  //
  gettimeofday(&after, NULL);
  timersub(&after, &before, &after);
  long long dtime = after.tv_sec * 1000000LL + after.tv_usec;
  printf("time: %lld us\n", dtime);
  
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
// ref:
// http://www.gnu.org/s/hello/manual/libc/Regular-Expressions.html
// http://blog.roodo.com/rocksaying/archives/3866523.html
// http://pubs.opengroup.org/onlinepubs/007908799/xsh/regex.h.html
// http://opensource.apple.com/source/Libc/Libc-594.9.4/regex/
// 
