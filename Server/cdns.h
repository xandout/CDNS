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



DNS_HEADER* parse_header(char* packet, int packet_length)
{
    DNS_HEADER* header = malloc(sizeof(DNS_HEADER));
//    int x = 0;
//    for(x = 0; x < 12; x++)
//    {
//        printf("%i", packet[x]);
//    }
    header->ID = packet[0] << 8 | packet[1];
    header->QR = ((packet[2] >> 1)  & 0x01); //Not certain this works yet
    //header->OC = 
    return header;

}