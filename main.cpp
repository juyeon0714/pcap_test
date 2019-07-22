#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcapheader.h>


struct _packet{
    ether_header* eth_header;
    iphdr* ip_header;
    tcphdr* tcp_header;
};





void usage() {

    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}



// mac : ether->daddr saddr
// ip: iphdr + 12: src +16: des
// port : tcphdr > th_dport, sport
// data: packet + 14 + iphdr->ihl*4 + tcpHdr->th_off*4
// len of data = ntohs(iphdr->tot_len) - iphdr->ihl*4 - tcp->th_off*4
// is has ip : ntohs(ethHdr->ether_type) == 0x800
// is has tcp : iphdr->protocol == 0x6
/*void (uint8_t *mac) {
    printf("mac : %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint8_t* ip) {
    printf("%u.%u.%u.%u.\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint8_t* port) {
    printf("%02d",port[0]<<8 )| port[1]; // port[0]*256
}

void print_data(char* data){
    printf("%u",data[0]);
}*/

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        //return -1;
    }

    //  char* dev = argv[1];
    char* dev = "ens33";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        struct _packet p;
        p.eth_header = (ether_header*)packet;
        printf("%u bytes captured\n", header->caplen);

        printf("src mac is ");
        print_mac(p.eth_header->ether_shost);
        printf("dst mac is ");
        print_mac(p.eth_header->ether_dhost);
        if(ntohs(p.eth_header->ether_type) == 0x0800){
            p.ip_header = (iphdr*)(packet+14);
            printf("src ip is ");
            print_ip((u_char*)p.ip_header+12);
            printf("dst ip is ");
            print_ip((u_char*)p.ip_header+16);
            if(p.ip_header->protocol==0x6){
                p.tcp_header = (tcphdr*)(packet+14 + p.ip_header->ihl*4);
                printf("src port is ");
                print_port(p.tcp_header->th_sport);
                printf("dst port is ");
                print_port(p.tcp_header->th_dport);
                printf("data is ");
                // if(lenOfData <10){
                //    print_data(p.tcp_header->th_off);
                // }
            }
        }



    }

    pcap_close(handle);
    return 0;
}
