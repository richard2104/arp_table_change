#include "my_pcap.h"

char *allocate_strmem(int len){
	void *tmp;
	tmp = (char *)malloc(len*sizeof(char));
	if (tmp != NULL){
		memset(tmp, 0, len*sizeof(char));
		return tmp;
	}
	else{
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
		exit(1);
	}
}

uint8_t *allocate_ustrmem (int len){
	void *tmp;
	tmp = (uint8_t *)malloc(len*sizeof(uint8_t));
	if (tmp != NULL){
		memset(tmp, 0, len*sizeof(uint8_t));
		return tmp;
	}
	else{
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
		exit(1);
	}
}


void GET_MYMAC(uint8_t *mac, char *interface) {
	int sd,i=0;
	struct ifreq ifr;

	if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    	perror ("socket() failed to get socket descriptor for using ioctl() ");
    	exit (-1);
  	}

  	// Use ioctl() to look up interface name and get its MAC address.
  	memset (&ifr, 0, sizeof (ifr));
  	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
   	 	perror ("ioctl() failed to get source MAC address ");
   		return (-1);
  	}
	close (sd);

	// Copy source MAC address.
  	memcpy (mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    // Report source MAC address to stdout.
  	printf ("MAC address for interface %s is ", interface);
  	for (i=0; i<5; i++) {
    	printf ("%02x:", mac[i]);
 	}
	printf("%02x\n",mac[5]);
}
void GET_MYIP(u_int8_t *ip_addr, char *interface) {
	int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    /* and more importantly */
    printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	memcpy(ip_addr, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IP_ADDR_LEN);
    
	close(fd);

}

void ARP_REQUEST(pcap_t *handle, u_char *mac_addr, struct in_addr *senderIP, struct in_addr *targetIP) {
	u_char* packet;
	u_char* recv_packet;
    struct ether_header etherHdr, *recv_ether; // <netinet/ether.h>
	struct arp_hdr_ arp_h, *recv_arp;

	struct pcap_pkthdr *header;
	int packet_len;
	int flag, i;
	struct in_addr recv_IP;
	u_char* recv_MAC;
	u_char* buf;
	u_char addr[4];
	
	//ether layer
	memcpy(etherHdr.ether_shost,mac_addr,ETHER_ADDR_LEN); // Ether_SRC == MY_MAC
	memcpy(etherHdr.ether_dhost,"\xff\xff\xff\xff\xff\xff",ETHER_ADDR_LEN); // Broadcast
	etherHdr.ether_type = htons(0x0806); // short! ARP 0x0806
	
	// arp layer
	arp_h.htype = htons(0x0001); // Hardware type
	arp_h.ptype = htons(ETHERTYPE_IP); // Protocol type
	arp_h.hlen = ETHER_ADDR_LEN; // Hardware size
	arp_h.plen = 4;				 // Protocol size
	arp_h.opcode = htons(1);	 // ARP request opcode: 1
	memcpy(arp_h.sender_mac,mac_addr,sizeof(arp_h.sender_mac));
	memcpy(arp_h.sender_ip,senderIP,sizeof(arp_h.sender_ip));
	memcpy(arp_h.target_mac,"\x00\x00\x00\x00\x00\x00",sizeof(arp_h.target_mac)); //don't know the target mac
	memcpy(arp_h.target_ip,targetIP,sizeof(arp_h.target_ip));

	// packet arrangement!
	packet = (u_char*) malloc(sizeof(etherHdr)+sizeof(arp_h));
	memcpy(packet, &etherHdr, sizeof(etherHdr));
	memcpy(packet + sizeof(etherHdr), &arp_h, sizeof(arp_h));
	packet_len = sizeof(etherHdr) + sizeof(arp_h);
	
	printf("\n[+] packet to send\n");
	for(i=0; i < sizeof(etherHdr) + sizeof(arp_h); i++){
		if(i != 0 && i%16 == 0)
			printf("\n");
		printf("%02x ", *(packet+i));
	}
	printf("end\n");
	// packet sending!
	while(1){
		// int pcap_sendpacket(pcap_t *p, const u_char *buf, int size);
		if(pcap_sendpacket(handle,packet,packet_len) == 0) break;
	}

	printf("\n[+] arp request completed!\n\n");

	while(1) {
		flag = pcap_next_ex(handle,&header,&recv_packet);
		if(flag == 0) {
			printf("[-] time out\n");
			if(pcap_sendpacket(handle,packet,packet_len) !=0){
				printf("[-] failed... restart the program!\n");
				exit(1);
			}
			else
				continue;
			
		}
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
		if (pcap_datalink(handle) != DLT_EN10MB) {
			printf("[-] it is not ether\n");
			exit(1);
		}
		
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

	}

}

void arp_table_inject(pcap_t *handle, u_char *my_mac, u_char *sender_mac, struct in_addr *senderIP, struct in_addr *targetIP) {
	


}
