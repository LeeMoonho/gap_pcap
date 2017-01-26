#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ip * iph; //in.h
struct tcphdr * tcph;

void pack_view(unsigned char * user, const struct pcap_pkthdr* h, const unsigned char * p)
{
  struct ether_header * et_hd;
  unsigned short eth_typ;
  int len = 0, i = 0;  

  et_hd = (struct ether_header *) p;

  p += sizeof(struct ether_header);

  eth_typ = ntohs(et_hd -> ether_type);

  if(eth_typ == ETHERTYPE_IP) //pcap.h
  {
    iph = (struct ip *) p;

    printf("Packet Type IP\n");
    printf("IP Version : %d\n",iph -> ip_v);
    printf("Header Len : %d\n",iph -> ip_hl);
    printf("TTL : %d\n",iph -> ip_ttl);
    printf("Src Add : %s\n",inet_ntoa(iph -> ip_src));
    printf("Dst Add : %s\n",inet_ntoa(iph -> ip_dst));
    printf("Src Mac : ");
    
    while(i < 6){
      printf("%02x ",et_hd -> ether_shost[i]);
      i++;
    }
    
    printf("\nDst Mac : ");

    i = 0;
    
    while(i < 6){
      printf("%02x ",et_hd -> ether_dhost[i]);
      i++;
    }

  }
  printf("\n");

  if (iph->ip_p == IPPROTO_TCP)
  {
    tcph = (struct tcphdr*)(p + iph->ip_hl * 4);
    printf("TCP port\n");
    printf("Src Port : %d\n" , ntohs(tcph->source));
    printf("Dst Port : %d\n" , ntohs(tcph->dest));
  }


  printf("packet\n");

  //Data

  while(len < h -> len)
  {
    printf("%02x ", *(p++));
    if(!(++len % 16))
    {
      printf("\n");
    }
  }
  printf("\n");

  return;
}


int main()
{
  char * dev;
  char error[PCAP_ERRBUF_SIZE];
  bpf_u_int32 net;
  bpf_u_int32 mask;
  pcap_t * pd;

  struct in_addr net_addr,mask_addr;


  if(!(dev = pcap_lookupdev(error)))
  {
    perror(error);
    return 0;
  }

  if(pcap_lookupnet(dev,&net, &mask,error) < 0)
  {
    perror(error);
    return 0;
  }

  net_addr.s_addr = net;
  mask_addr.s_addr = mask;

  printf("Dev : %s\n",dev);
  printf("Net Address : %s\n",inet_ntoa(net_addr));
  printf("Net Mask : %s\n",inet_ntoa(mask_addr) );

  if ((pd = pcap_open_live(dev,1024,1,100,error)) == NULL)
  {
    perror(error);
    return 0;
  }
  if (pcap_loop(pd,0,pack_view,0) < 0)
  {
    perror(error);
    return 0;
  }

  pcap_close(pd);
  return 0;
}
