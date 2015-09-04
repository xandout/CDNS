#include <stdio.h>
#include <winsock.h>
#include <stdlib.h>
#include "address_functions.h"

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

    strtosockaddr_in("192.168.1.5", &SERVER);
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

    typedef struct {
        unsigned int ID : 16;
        unsigned int QR : 1;
        unsigned int OC : 4;
        unsigned int AA : 1;
        unsigned int TC : 1;
        unsigned int RD : 1;
        unsigned int RA : 1;
        unsigned int Z : 1;
        unsigned int AD : 1;
        unsigned int CD : 1;
        unsigned int RCODE : 4;
        unsigned int QCOUNT : 16;
        unsigned int ANSCOUNT : 16;
        unsigned int AUTHCOUNT : 16;
        unsigned int ARCOUNT : 16;
    } DNS_HEADER;

    while(1) {
        CLIENT_LENGTH = (int)sizeof(struct sockaddr_in);

        BYTES_RECVD = recvfrom(sd, BUFFER, 4096, 0, (struct sockaddr*)&CLIENT, &CLIENT_LENGTH);
        if(BYTES_RECVD < 0) {
            fprintf(stderr, "Could not recieve datagram\n");
            closesocket(sd);
            WSACleanup();
            exit(0);
        }

        int STARTQ = 0;
        int STOPQ = BYTES_RECVD - 5;
        char Q[STOPQ - 13];
        Q[STOPQ - 13] = '\0';
        printf("------\n");
        int x = 0;
        for(STARTQ = 13; STARTQ < STOPQ; STARTQ++) {

            if(BUFFER[STARTQ] < 31)
                BUFFER[STARTQ] = 46;

            Q[x] = BUFFER[STARTQ];
            x++;
            if(argc == 4) {
                if(strcmp(argv[3], "PRINTBYTES") == 0)
                    printf("%i : %c\n", BUFFER[STARTQ], BUFFER[STARTQ]);
            }
        }
        printf("%s\n", Q);
    }
    closesocket(sd);
    WSACleanup();

    return 0;
}