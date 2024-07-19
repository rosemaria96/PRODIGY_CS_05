#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>


void packet_handler(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("Protocol: %d\n", ip_header->ip_p);
        printf("Payload Length: %d\n", ntohs(ip_header->ip_len));
        printf("\n");
    }
}

int main() {
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t *handle; 

   
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    printf("Using device: %s\n", dev);

    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

   
    pcap_loop(handle, 10, packet_handler, NULL);

    // Close the session
    pcap_close(handle);
    return 0;
}
