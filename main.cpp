#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

struct etherheader{
	unsigned char srcmac[6];
	unsigned char dstmac[6];
	uint16_t type;
};
struct ip_header{
	unsigned char version[1];
	unsigned char SerField[1];
	unsigned char length[2];
	unsigned char identification[2];
	unsigned char flag[2];
	unsigned char ttl[1];
	unsigned char protocol[1];
	unsigned char headersum[2];
	unsigned char dstip[4];
	unsigned char srcip[4];
};

struct tcp_header{
	u_short src_port;
	u_short dst_port;
	unsigned char seqnum[4];
	unsigned char dstnum[4];
	unsigned char flag[2];
	unsigned char windowsize[2];
	unsigned char checksum[2];
	unsigned char urgent_pointer[2];
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 1) {
    usage();
    return -1;
  }

  char* dev = "enp0s3";
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  int i = 1;	
  while (i<3) {

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct etherheader *eth =(struct etherheader*)packet;
    packet += sizeof(etherheader);
    struct ip_header *ip = (struct ip_header*)packet;
    packet+= sizeof(ip_header);
    struct tcp_header *tcp = (struct tcp_header*)packet;
    printf("srcmac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->srcmac[0],eth->srcmac[1],eth->srcmac[2],eth->srcmac[3],eth->srcmac[4],eth->srcmac[5]);
    printf("dstmac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dstmac[0],eth->dstmac[1],eth->dstmac[2],eth->dstmac[3],eth->dstmac[4],eth->dstmac[5]);
    printf("version : %.01x\n", ip->version[0]);
    printf("type is is is %x\n  ", ntohs(eth->type));
     if(ntohs(eth->type)==0x800)
	    printf("\t\t\t\ ip type is coming..\n");
	
    
    printf("srcip : %d.%d.%d.%d\n", ip->srcip[0],ip->srcip[1],ip->srcip[2],ip->srcip[3]);
    printf("dstip : %d.%d.%d.%d\n", ip->dstip[0],ip->dstip[1],ip->dstip[2],ip->dstip[3]);
    printf(" Src port: %d\n", ntohs(tcp->src_port));
    printf(" dst port: %d\n", ntohs(tcp->dst_port));
    
    unsigned int test=( header-> caplen);
    
    for(int j=0; j<test; j++)
    {
	    printf("%x ", packet[j]);
    }
    printf(": %d ", i++);
    printf("  %d bytes captured\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}
