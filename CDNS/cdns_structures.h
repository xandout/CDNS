//
//  cdns_structures.h
//  CDNS
//
//  Created by mturner on 2/4/16.
//  Copyright © 2016 mturner. All rights reserved.
//

#ifndef cdns_structures_h
#define cdns_structures_h

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DNS_TYPE_A      1
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_PTR   12
#define DNS_TYPE_MX    15
#define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_SRV   33
#define DNS_TYPE_ANY  255
#define DNS_TYPE_NSEC  47

typedef struct {
    unsigned int ID : 16;
    unsigned int QR : 1;         // 00000001 1
    unsigned int OC : 4;         // 00011110 30
    unsigned int AA : 1;         // 00100000 32
    unsigned int TC : 1;         // 01000000 64
    unsigned int RD : 1;         // 10000000 128 End of B3
    unsigned int RA : 1;         // 00000001 1
    unsigned int Z : 1;          // 00000010 2
    unsigned int AD : 1;         // 00000100 4
    unsigned int CD : 1;         // 00001000 8
    unsigned int RCODE : 4;      // 11110000 240 End of B4
    unsigned int QCOUNT : 16;    // B5
    unsigned int ANSCOUNT : 16;  // B7
    unsigned int AUTHCOUNT : 16; // B9
    unsigned int ARCOUNT : 16;   // B11
} DNS_HEADER;

DNS_HEADER* parse_header(char* packet, int packet_length)
{
    DNS_HEADER* header = malloc(sizeof(DNS_HEADER));
    header->ID = packet[0] << 8 | packet[1];
    header->QR = ((packet[2] & 1) >> 1); // Not certain this works yet
    header->OC = ((packet[2] & 30) >> 1);
    header->AA = ((packet[2] & 32) >> 1);
    header->TC = ((packet[2] & 64) >> 1);
    header->RD = ((packet[2] & 128) >> 1);
    
    header->RA = ((packet[3] & 1) >> 1);
    header->Z = ((packet[3] & 2) >> 1);
    header->AD = ((packet[3] & 4) >> 1);
    header->CD = ((packet[3] & 8) >> 1);
    header->RCODE = ((packet[3] & 240) >> 1);
    
    header->QCOUNT = packet[4] << 8 | packet[5];
    header->ANSCOUNT = packet[6] << 8 | packet[7];
    header->AUTHCOUNT = packet[8] << 8 | packet[9];
    header->ARCOUNT = packet[10] << 8 | packet[11];
    return header;
}

typedef struct {
    char* QUERY;
    unsigned int TYPE : 16;
    unsigned int CLASS : 16;
} QUESTION;

QUESTION* parse_question(char* packet, long packet_length)
{
    QUESTION* question = malloc(sizeof(QUESTION));
    
    
    char* qstart = &packet[sizeof(DNS_HEADER)];
    int iterator = 1; /* Use 1 here to strip leading char */
    for (iterator = 1; qstart[iterator] != '\0'; iterator++) {
        if (qstart[iterator] < 31) {
            qstart[iterator] = 46; //put periods anywhere invalid char is found
        }
    }
    question->QUERY = malloc(sizeof(qstart));
    strcpy(question->QUERY, qstart);

    
    //Parse TYPE
    question->TYPE = packet[packet_length - 2] << 8 | packet[packet_length - 3];
    //END Parse TYPE
    
    //Parse CLASS
    //I don't trust this, it works but it seems wrong
    question->CLASS = packet[packet_length - 1] << 8 | packet[packet_length];
    //END Parse CLASS
    return question;
}



#endif /* cdns_structures_h */
