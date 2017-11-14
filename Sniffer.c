#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h> 
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
int count=0;
struct if_nameindex interfaces(void);
void ProcessIPv4Packet(unsigned char* , int );
void print_ip_header(unsigned char* , int );
void print_tcp_packet(unsigned char* , int);
void print_udp_packet(unsigned char * , int);
void print_icmp_packet(unsigned char*  , int );
void PrintData (unsigned char* , int);
struct sockaddr_in source,dest;
int i,j;
FILE *fp;
int main(int argc, char *argv[])
{
	 printf(">>>>>>>> Packet sniffing Program <<<<<<<<<\nPlease check dump.txt for detailed information of frames\n\n");
	fp=fopen("dump.txt","w");
	int sockfd, i;
	struct ifreq ifoptions;	/* set promiscuous mode */
	char *ifName;
	if(argc>1)
	{
		ifName=argv[1];
	}
	else
	{
		struct if_nameindex interface=interfaces();
		ifName=interface.if_name;
	}
	if ((sockfd = socket(PF_PACKET, SOCK_RAW,htons(0x0003))) == -1) {
		perror("listener: socket");	
		return -1;
	}
	// Set interface to promiscuous mode
	strcpy(ifoptions.ifr_name, ifName);
       
	ioctl(sockfd, 0x8913, &ifoptions);
	ifoptions.ifr_flags |= 0x100;
	ioctl(sockfd, 0x8914, &ifoptions);
	// Binding to interface 
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName,strlen(ifName)) == -1)	{
		perror("Binding : socket");	
		exit(0);
	}
	unsigned char *buffer = (unsigned char *)malloc(ETH_FRAME_LEN);
	while(1)
	{
	    fp=fopen("dump.txt","a");
            int receivedBytes = recvfrom(sockfd, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
	    int packetSize=receivedBytes-18;
	    unsigned char* hex=((unsigned char*)buffer);
            printf("\n%d bytes received  ", receivedBytes);
	    fprintf(fp, "*********** Ethernet Header Information: Frame %d************\n",++count);
	    printf("Frame %d  %02X:%02X:%02X:%02X:%02X:%02X > %02X:%02X:%02X:%02X:%02X:%02X  ",count,hex[0],hex[1],hex[2],hex[3],hex[4],hex[5],hex[6],hex[7],hex[8],hex[9],hex[10],hex[11]);
	    fprintf(fp,"Source MAC %02X:%02X:%02X:%02X:%02X:%02X\n",hex[0],hex[1],hex[2],hex[3],hex[4],hex[5]);
	    fprintf(fp,"Destination MAC %02X:%02X:%02X:%02X:%02X:%02X\n",hex[6],hex[7],hex[8],hex[9],hex[10],hex[11]);
	    int etype=(hex[12]*16*16)+hex[13];
	    fprintf(fp,"Ether type : %02X %02X",hex[12],hex[13]);
	    int ether_types[50]={0x0800, 0x0806, 0x0842, 0x22F3, 0x22EA, 0x6003, 0x8035, 0x809B, 0x80F3, 0x8100, 0x8137, 0x8204, 0x86DD, 0x8808, 0x8809, 0x8819, 0x8847 , 0x8848, 0x8863, 0x8864, 0x886D, 0x8870, 0x887B, 0x888E, 0x8892,0x889A, 0x88A2, 0x88A4, 0x88A8, 0x88AB, 0x88B8, 0x88B9, 0x88BA, 0x88CC, 0x88CD, 0x88DC, 0x88E1, 0x88E3, 0x88E5, 0x88E7, 0x88F7, 0x88FB, 0x8902, 0x8906, 0x8914, 0x8915, 0x891D, 0x892F, 0x9000, 0x9100};
	    char *ether_type_names[]={"Internet Protocol version 4 (IPv4)", "Address Resolution Protocol (ARP)", "Wake-on-LAN[7]", "IETF TRILL Protocol", "Stream Reservation Protocol", "DECnet Phase IV", "Reverse Address Resolution Protocol", "AppleTalk (Ethertalk)", "AppleTalk Address Resolution Protocol (AARP)", "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[8]", "IPX", "QNX Qnet", "Internet Protocol Version 6 (IPv6)", "Ethernet flow control", "Ethernet Slow Protocols[9]", "CobraNet", "MPLS unicast", "MPLS multicast", "PPPoE Discovery Stage", "PPPoE Session Stage", "Intel Advanced Networking Services [10]", "Jumbo Frames (Obsoleted draft-ietf-isis-ext-eth-01)", "HomePlug 1.0 MME", "EAP over LAN (IEEE 802.1X)", "PROFINET Protocol", "HyperSCSI (SCSI over Ethernet)", "ATA over Ethernet", "EtherCAT Protocol", "Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[8]", "Ethernet Powerlink[citation needed]", "GOOSE (Generic Object Oriented Substation event)", "GSE (Generic Substation Events) Management Services", "SV (Sampled Value Transmission)", "Link Layer Discovery Protocol (LLDP)", "SERCOS III", "WSMP, WAVE Short Message Protocol", "HomePlug AV MME[citation needed]", "Media Redundancy Protocol (IEC62439-2)", "MAC security (IEEE 802.1AE)", "Provider Backbone Bridges (PBB) (IEEE 802.1ah)", "Precision Time Protocol (PTP) over Ethernet (IEEE 1588)", "Parallel Redundancy Protocol (PRP)", "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)", "Fibre Channel over Ethernet (FCoE)", "FCoE Initialization Protocol", "RDMA over Converged Ethernet (RoCE)", "TTEthernet Protocol Control Frame (TTE)", "High-availability Seamless Redundancy (HSR)", "Ethernet Configuration Testing Protocol[11]", "VLAN-tagged (IEEE 802.1Q) frame with double tagging"};
            int i,j;
	    for (i = 0; i < 50; i++)
            {
	       if(etype==ether_types[i])
	       {
			fprintf(fp,"  %s \n",ether_type_names[i]);
			printf(" %s  ",ether_type_names[i]);
			break;
	       }
            }
	    unsigned char* packet=(unsigned char *)malloc(receivedBytes);
	    for (i=14,j=0; i < receivedBytes-4;i++,j++)
	    {
		packet[j]=hex[i];
	    }
 	    switch(etype)
	    {
		case 0x800:
			fprintf(fp,"IPv4 Packet\n");
			ProcessIPv4Packet(packet, packetSize);
			break;
		default:
			fprintf (fp,"??????????? Skipping Packet ????????????????\n");
	    }
	    fprintf(fp,"\n################# HEX DUMP ###############\n");
            for (i = 0; i < receivedBytes; i++)
            {
               fprintf(fp,"%02X ", ((unsigned char*)buffer)[i]);
            }
	    fprintf(fp,"\n##########################################\n");

            fprintf(fp,"\n\n");
	    fclose(fp);
       }
}

struct if_nameindex interfaces(void)
{
    struct if_nameindex *interfaces_list, *interface;
    int i=0,j;
    printf("############# Available interfaces ############\n");
    interfaces_list = if_nameindex();
    if ( interfaces_list != NULL )
    {
        for (interface = interfaces_list; interface->if_index != 0 || interface->if_name != NULL; interface++)
        {
           printf("%d.%s\n", ++i,interface->if_name);
        }
    }
    printf("Select the interface to set start sniffing : ");
    scanf("%d",&j);
    return interfaces_list[--j];
}

void ProcessIPv4Packet(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            printf("ICMP Packet");
	    print_icmp_packet(buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            printf("IGMP Packet");
            break;
         
        case 6:  //TCP Protocol
            printf("TCP Packet");
            print_tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
            printf("UDP Packet");
            print_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            printf("Other Packet");
            break;
    }
    //printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",tcp,udp,icmp,igmp,others,total);
}
void print_ip_header(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(fp,"\n");
    fprintf(fp,"IP Header\n");
    fprintf(fp,"   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(fp,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(fp,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(fp,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(fp,"   |-Identification    : %d\n",ntohs(iph->id));
    fprintf(fp,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(fp,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(fp,"   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(fp,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(fp,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
             
    fprintf(fp,"***********************TCP Packet*************************\n");    
         
    print_ip_header(Buffer,Size);
         
    fprintf(fp,"\n");
    fprintf(fp,"TCP Header\n");
    fprintf(fp,"   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(fp,"   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(fp,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(fp,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(fp,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(fp,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(fp,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(fp,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(fp,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(fp,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(fp,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(fp,"   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(fp,"   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(fp,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(fp,"\n");
    fprintf(fp,"                        DATA Dump                         ");
    fprintf(fp,"\n");
         
    fprintf(fp,"IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(fp,"TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(fp,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
                         
    fprintf(fp,"\n###########################################################\n");
}
 
void print_udp_packet(unsigned char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
     
    fprintf(fp,"***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,Size);           
     
    fprintf(fp,"\nUDP Header\n");
    fprintf(fp,"   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(fp,"   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(fp,"   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(fp,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(fp,"\n");
    fprintf(fp,"IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    fprintf(fp,"UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    fprintf(fp,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));
     
    fprintf(fp,"\n###########################################################\n");
}
 
void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
             
    fprintf(fp,"***********************ICMP Packet*************************\n");   
     
    print_ip_header(Buffer , Size);
             
    fprintf(fp,"\n");
         
    fprintf(fp,"ICMP Header\n");
    fprintf(fp,"   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11) 
        fprintf(fp,"  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
        fprintf(fp,"  (ICMP Echo Reply)\n");
    fprintf(fp,"   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(fp,"   |-Checksum : %d\n",ntohs(icmph->checksum));
    fprintf(fp,"\n");
 
    fprintf(fp,"IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(fp,"UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    fprintf(fp,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));
     
    fprintf(fp,"\n###########################################################\n");
}
 
void PrintData (unsigned char* data , int Size)
{
     
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(fp,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(fp,"%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(fp,"."); //otherwise print a dot
            }
            fprintf(fp,"\n");
        } 
         
        if(i%16==0) fprintf(fp,"   ");
            fprintf(fp," %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(fp,"   "); //extra spaces
             
            fprintf(fp,"         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(fp,"%c",(unsigned char)data[j]);
                else fprintf(fp,".");
            }
            fprintf(fp,"\n");
        }
    }
}
