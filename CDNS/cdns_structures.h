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
#define DNS_TYPE_SOA    6
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

//typedef struct {
//    unsigned int ID : 16;        // B0
//    unsigned int FLAGS : 16;     // B2
//    unsigned int QCOUNT : 16;    // B4
//    unsigned int ANSCOUNT : 16;  // B6
//    unsigned int AUTHCOUNT : 16; // B8
//    unsigned int ARCOUNT : 16;   // B10
//} DNS_HEADER;

typedef struct {
    unsigned char* QUERY;
    unsigned int TYPE : 16;
    unsigned int CLASS : 16;
} QUESTION;

typedef struct {
    unsigned char* NAME;
    unsigned int TYPE : 16;
    unsigned int CLASS : 16;
    unsigned long TTL : 32;
    unsigned int D_LENGTH : 16;
    unsigned int* DATA;
}DNS_ANSWER_RR;

typedef struct {
    DNS_HEADER header;
    QUESTION question;
    DNS_ANSWER_RR answer;
} DNS_RESPONSE;

//DNS_ANSWER_RR* make_answer(unsigned char* name, unsigned char* data, unsigned int type, unsigned int dclass, unsigned long ttl, unsigned int dlength){
//    DNS_ANSWER_RR* ans = malloc(sizeof(DNS_ANSWER_RR));
//    
//    ans->NAME = name;
//    ans->TYPE = type;
//    ans->CLASS = dclass;
//    ans->TTL = ttl;
//    ans->D_LENGTH = dlength;
//    ans->DATA = data;
//    
//    return ans;
//}

DNS_HEADER* parse_header(unsigned char* packet, long packet_length)
{
    DNS_HEADER* header = malloc(sizeof(DNS_HEADER));
    memset(header, 0, sizeof(DNS_HEADER));
    header->ID = packet[0] << 8 | packet[1]; //This should be possible with bit shifting but fails if packet[0] has leading 0s
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

QUESTION* parse_question(unsigned char* packet, long packet_length)
{
    QUESTION* question = malloc(sizeof(QUESTION));
    
    
    unsigned char* qstart = (unsigned char*)&packet[sizeof(DNS_HEADER)];
    int iterator = 1; /* Use 1 here to strip leading char */
    for (iterator = 1; qstart[iterator] != '\0'; iterator++) {
        if (qstart[iterator] < 31) {
            qstart[iterator] = 46; //put periods anywhere invalid char is found
        }
    }
    question->QUERY = malloc(sizeof(qstart));
    memcpy(question->QUERY, qstart, packet_length - sizeof(DNS_HEADER));
    
    long last_byte = packet_length - 1;
    
    question->CLASS = packet[last_byte - 1] << 8 | packet[last_byte];
    question->TYPE = packet[last_byte - 3] << 8 | packet[last_byte - 2];
    return question;
}



#endif /* cdns_structures_h */
