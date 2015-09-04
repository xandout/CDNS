#include <winsock.h>
#include <stdio.h>


void strtosockaddr_in(char dq_addr[], struct sockaddr_in* sock){
    int OCT1, OCT2, OCT3, OCT4;
    if(sscanf(dq_addr, "%d.%d.%d.%d", &OCT1, &OCT2, &OCT3, &OCT4) == 4)
    {
        sock->sin_addr.S_un.S_un_b.s_b1 = (unsigned char)OCT1;
    sock->sin_addr.S_un.S_un_b.s_b2 = (unsigned char)OCT2;
    sock->sin_addr.S_un.S_un_b.s_b3 = (unsigned char)OCT3;
    sock->sin_addr.S_un.S_un_b.s_b4 = (unsigned char)OCT4;

    }
    fprintf(stderr, "Unable to parse address: %s.  Using 0.0.0.0 instead\n", dq_addr);

}