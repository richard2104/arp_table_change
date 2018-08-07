#include "my_pcap.h"

struct addr{
    uint8_t mac[6];
    uint8_t ip[4];
};

void GET_MYMACIP(struct addr *addr, char *interface) {
	int sd,i=0;
	struct ifreq ifr;	// ethernet structure

	if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    	perror ("socket() failed to get socket descriptor for using ioctl() ");
    	exit (-1);
  	}

  	// Use ioctl() to look up interface name and get its MAC address.
  	memset (&ifr, 0, sizeof (ifr));
  	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));

  	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
   	 	perror ("ioctl() failed to get source MAC address ");
   		return ;
  	}

	// Copy source MAC & IP address.
  	memcpy (addr->mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	memcpy (addr->ip, &(((struct sockaddr_in* ) &ifr.ifr_addr)->sin_addr),4 * sizeof (uint8_t));

    // Report source MAC address to stdout.
  	printf ("My MAC address for interface %s is ", interface);
  	for (i=0; i<5; i++) printf ("%02x:", addr->mac[i]);
	printf("%02x\n", addr->mac[5]);

	// Report source IP address to stdout.
  	printf ("My IP address for interface %s is ", interface);
	for (i=0; i<3; i++) printf("%d.", addr->ip[i]);
	printf("%d\n", addr->ip[3]);

	close(sd);

}

void gen_arp_packet(uint8_t *packet, uint8_t *sourcemac, uint8_t *destmac, uint8_t *sourceip, uint8_t *destip, u_int16_t opcode ) {
	struct ether_header *etharea;
	struct arp_hdr_ *arparea;

	etharea = (struct ether_header *)malloc(sizeof(struct ether_header));
	arparea = (struct arp_hdr_ *)malloc(sizeof(struct arp_hdr_));

	// ether layer
	if(destmac != NULL)
		memcpy(etharea->ether_dhost, destmac, ETHER_ADDR_LEN);
	else
		memcpy(etharea->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
	memcpy(etharea->ether_shost, sourcemac, ETHER_ADDR_LEN);
	etharea->ether_type = htons(ETHERTYPE_ARP);

	// arp layer
	arparea->htype = htons(ARPHRD_ETHER);
	arparea->ptype = htons(ETHERTYPE_IP);
	arparea->hlen = 6;
	arparea->plen = 4;
	arparea->opcode = htons(opcode);
	memcpy(arparea->sender_mac, sourcemac, ETHER_ADDR_LEN);
	memcpy(arparea->sender_ip, sourceip, IP_ADDR_LEN);	

	if(destmac != NULL)
		memcpy(arparea->target_mac, destmac, ETHER_ADDR_LEN);
	else
		memcpy(arparea->target_mac, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
	memcpy(arparea->target_ip, destip, IP_ADDR_LEN);
	
	memset(packet, '\x00', sizeof(struct ether_header) + sizeof(struct arp_hdr_));   // 0 initialize
	memcpy(packet, &etharea, sizeof(struct ether_header));                // ether first!
	memcpy(packet + sizeof(struct ether_header), &arparea, sizeof(struct arp_hdr_));   // arp next!

}

void pcap_send_check(pcap_t* handle, uint8_t *packet) {
	if(pcap_sendpacket(handle,packet,sizeof(struct ether_header)+sizeof(struct arp_hdr_))==-1) {
    	free(packet);
        pcap_perror(handle,0);
        pcap_close(handle);
        exit(1);
    }
}
