#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <pcap.h>

void getPacket(u_char*, const struct pcap_pkthdr*, const u_char*);
void usage();

int main(int argc, char** argv){
	char errBuf[PCAP_ERRBUF_SIZE], filename[50];
	char* dev;
	pcap_t* device;
	int num, id = 0;
	
	/* find usable device */
	dev = pcap_lookupdev(errBuf);
	if(dev == NULL){
		printf("error finding device.\n");
		printf("error:%s\n", errBuf);
		exit(0);
	}
	
	if(argc == 3){
		/* sudo ./main -r <filename>.pcap */
		if(strncmp(argv[1], "-r", 2) == 0){
			strcpy(filename, argv[2]);
			device = pcap_open_offline(filename, errBuf);
			num = -1;
		}
		/* sudo ./main -online <num> */
		else if(strncmp(argv[1], "-online", 7) == 0){
			device = pcap_open_live(dev, 65535, 1, 0, errBuf);
			num = atoi(argv[2]);
		}
		else
			usage();
	}
	else if(argc == 2){
		/* sudo ./main -online */
		if(strncmp(argv[1], "-online", 7) == 0){
			device = pcap_open_live(dev, 65535, 1, 0, errBuf);
			num = -1;
		}
		else
			usage();
	}
	else
		usage();
	
	printf("device:%s\n", dev);
	printf("pcap loop starts.\n");
	pcap_loop(device, num, getPacket, (u_char*)&id);
	
	printf("pcap closing...\n");
	pcap_close(device);
	printf("pcap closed.\n");

	return 0;
}


void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet){
	int * id = (int *)arg;
	char tmp[200];
	
	(*id)++;
	printf("id: %d\n", *id);
	
	/*
	printf("Packet length: %d\n", pkthdr->len);
	
	printf("packet: \n");
	for(i = 0 ; i < pkthdr->len ; i++)
		printf("%02x ", packet[i]);
	*/
	
	
	printf("time: %s", ctime((const time_t* )&pkthdr->ts.tv_sec)); 
	
	printf("Src MAC Address: ");
	for(int i = 6 ; i < 12-1 ; i++)
		printf("%02x-", packet[i]);
	printf("%02x\n", packet[11]);
	
	printf("Dst MAC Address: ");
	for(int i = 0 ; i < 6-1 ; i++)
		printf("%02x-", packet[i]);
	printf("%02x\n", packet[5]);
	
	printf("Ethernet type: ");
	printf("0x%02x%02x\n", packet[12], packet[13]);
	
	/* IP:Ethernet type = 0x0800 */
	if(packet[12] == 8 && packet[13] == 0)
	{
		printf("Type: IP\n");
		
		printf("Src IP Address: ");
		for(int i = 26 ; i < 29 ; i++)
			printf("%d.", packet[i]);
		printf("%d\n", packet[29]);
		
		printf("Dst IP Address: ");
		for(int i = 30 ; i < 33 ; i++)
			printf("%d.", packet[i]);
		printf("%d\n", packet[33]);
		
		printf("Protocol: ");
		if(packet[23] == 6)
			printf("TCP\n");
		else if(packet[23] == 17)
			printf("UDP\n");
		else
			printf("others(not TCP/UDP)\n");
		
		if(packet[23] == 6 || packet[23] == 17){
			printf("Src port: %d\n", packet[34] * 256 + packet[35]);
			printf("Dst port: %d\n", packet[36] * 256 + packet[37]);
		}
	}

	printf("\n\n");
}

void usage(){
	printf("wrong format.\nUsage:\nsudo ./main -r <filename>.pcap\nsudo ./main -online <num>\nsudo ./main -online\n");
	exit(0);
}


