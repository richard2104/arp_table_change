#include "my_pcap.h"

void callback(u_char *p, const struct pcap_pkthdr *pkthdr, const u_char *packet);


int main(int argc, char* argv[]) {
   
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE]; // 256
    pcap_t *pcd;
    uint8_t *my_mac; //or just my_mac[ETHER_ADDR_LEN] and not use ustrmem
	uint8_t *my_ip;
	struct in_addr senderIP, targetIP, myIP;
    
	int length = 0;
    unsigned char packet[1500];
	
    if (argc != 4){
        puts("[-]Usage : ./arp_send [interface] [sender_ip] [target_ip]");
        return -1;
    }
	
	my_mac = allocate_ustrmem(ETHER_ADDR_LEN);
	my_ip  = allocate_ustrmem(IP_ADDR_LEN);
	
	dev = argv[1];
	printf("\n[+] device : %s\n",dev);
	GET_MYMAC(my_mac, argv[1]); // saved in my_mac & print out
	GET_MYIP(my_ip,argv[1]); //print out my_ip

	// argv[2],argv[3] to sender and target
	inet_pton(AF_INET,argv[2],&senderIP.s_addr); //10진수 IP 주소를 2진수 IP 주소로 변환하는 함수
	inet_pton(AF_INET,argv[3],&targetIP.s_addr); //senderIP: victim / targetIP == gateway

	pcd = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(pcd == NULL){
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
		exit(1);
	}
    //Ethernet header check
    if (pcap_datalink(pcd) != DLT_EN10MB){
        fprintf(stderr, "Device %s doesn't provide Ethernet headers\n", argv[1]);
        exit(1);
    }

	// me(attacker) request to victim for mac address.
	ARP_REQUEST(pcd,my_mac,my_ip,&senderIP); // sender == victim / target == gateway
	

}




