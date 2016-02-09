#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h> /* memset */
#include "cdns_structures.h"
#define BUFLEN 4096 /* just in case */
#define PORT 53 /* default port */
#define TOGGLE_BIT(val, bitIndex) val ^= (1 << bitIndex)

void failure(char *s)
{
    perror(s);
}
int main(void)
{
    struct sockaddr_in ADDR_SERV, ADDR_CLIENT;
    int s, slen=sizeof(ADDR_CLIENT);
    unsigned char buf[BUFLEN];
    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
        failure("socket");
    memset((char *) &ADDR_SERV, 0, sizeof(ADDR_SERV));
    ADDR_SERV.sin_family = AF_INET;
    ADDR_SERV.sin_port = htons(PORT);
    ADDR_SERV.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (const struct sockaddr*)&ADDR_SERV, sizeof(ADDR_SERV))==-1){
        failure("Could not bind()");
    }
    
    while (1) {
        memset(&buf, 0, BUFLEN); /* remove old data */
        long BYTES_RECVD = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr*)&ADDR_CLIENT, (socklen_t*)&slen);
        if (BYTES_RECVD==-1){
            failure("recvfrom()");
            break;
        }
        // Now the magic happens
        

        
        
        
        
        QUESTION* qq = parse_question(buf, BYTES_RECVD);
        DNS_HEADER* dh = parse_header(buf, BYTES_RECVD);
        
        printf("QUERY TYPE:%d from %s:%d is %s\n", qq->TYPE, inet_ntoa(ADDR_CLIENT.sin_addr),
               ntohs(ADDR_CLIENT.sin_port), qq->QUERY);
        
        struct in_addr t;
        inet_aton("192.168.1.1", &t);
        
        
        
        
        DNS_ANSWER_RR* rr = malloc(sizeof(DNS_ANSWER_RR));
        memset(rr, 0, sizeof(DNS_ANSWER_RR));
        rr->TTL = 3600;
        rr->NAME = qq->QUERY;
        rr->CLASS = qq->CLASS;
        rr->TYPE = qq->TYPE;
        rr->D_LENGTH = sizeof(t.s_addr);
        rr->DATA = &t.s_addr;
        
        
        DNS_RESPONSE* dr = malloc(sizeof(DNS_RESPONSE));
        memset(dr, 0, sizeof(*dr));
        memcpy(( void*)&dr->header, dh, sizeof(&dh));
        
        dr->header.ID = htons(dr->header.ID);
        dr->header.ANSCOUNT = htons(1);
        dr->header.QCOUNT = htons(1);
        
        
        printf("DR is %lu bytes", sizeof(*dr));
        
        sendto(s, (const void*)dr, sizeof(*dr), 0, (struct sockaddr*)&ADDR_CLIENT, sizeof(ADDR_CLIENT));
        
        
    }
    
    close(s);
    return 0;
}