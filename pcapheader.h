#include <stdint.h>
#include <stdio.h>
#include <pcap.h>

#ifndef PCAPHEADER_H
#define PCAPHEADER_H

#endif // PCAPHEADER_H

/*struct packet{
    ether_header* eth_header;
    iphdr* ip_header;
    tcphdr* tcp_header;
};*/

void print_mac(uint8_t * mac) {
    printf("mac : %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

uint16_t ntohs(uint16_t n) {
    //return ((n & 0x00FF << 8 | n & 0xFF00 >> 8));
    return n << 8 | n >> 8;
}

void print_port(uint16_t port) {
    printf("%02d", ntohs(port)); // port[0]*256
}

void print_data(char* data){
    printf("%u",data[0]);
}


/*int lenOfData(){

    ntohs(iphdr->tot_len) - iphdr->ihl*4 - tcp->th_off*4;
    return length;
}
*/

