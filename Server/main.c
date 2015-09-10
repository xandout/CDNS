#include <stdio.h>
#include <winsock.h>
#include <stdlib.h>
#include "address_functions.h"
#include "cdns.h"

int main(int argc, char** argv)
{
    WSADATA w;
    unsigned short PORT = 53;
    int CLIENT_LENGTH;
    int BYTES_RECVD;
    SOCKET sd;
    struct sockaddr_in SERVER, CLIENT;
    char BUFFER[4096];
    struct hostent* HP;
    memset((void*)&SERVER, '\0', sizeof(struct sockaddr_in));
    SERVER.sin_family = AF_INET;
    SERVER.sin_port = htons(PORT);

    //    Open winsock

    if(WSAStartup(0x0101, &w) != 0) {
        fprintf(stderr, "Could not get winsock\n");
        exit(0);
    }

    sd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sd == INVALID_SOCKET) {
        fprintf(stderr, "Could not create socket\n");
        WSACleanup();
        exit(0);
    }

    strtosockaddr_in("0.0.0.0", &SERVER);
    if(bind(sd, (struct sockaddr*)&SERVER, sizeof(struct sockaddr_in)) == -1) {
        fprintf(stderr, "Could not bind to socket\n");
        closesocket(sd);
        WSACleanup();
        exit(0);
    }
    printf("Server running on %u.%u.%u.%u\n",
           (unsigned char)SERVER.sin_addr.S_un.S_un_b.s_b1,
           (unsigned char)SERVER.sin_addr.S_un.S_un_b.s_b2,
           (unsigned char)SERVER.sin_addr.S_un.S_un_b.s_b3,
           (unsigned char)SERVER.sin_addr.S_un.S_un_b.s_b4);
    printf("Press CTRL + C to quit\n");

    
    while(1) {
        CLIENT_LENGTH = (int)sizeof(struct sockaddr_in);

        BYTES_RECVD = recvfrom(sd, BUFFER, 4096, 0, (struct sockaddr*)&CLIENT, &CLIENT_LENGTH);
        if(BYTES_RECVD < 0) {
            fprintf(stderr, "Could not recieve datagram\n");
            closesocket(sd);
            WSACleanup();
            exit(0);
        }      
        QUESTION* qq = parse_question(&BUFFER, BYTES_RECVD);
        printf("QUERY TYPE:%d is %s\n", qq->TYPE, qq->QUERY);
    }
    closesocket(sd);
    WSACleanup();

    return 0;
}