/*
 * Author: Samuel Hetteš, ID: 110968
 * Subject: Computer and communication networks
 * Assignment: Network communication analyzer
 * IDE: Code::Blocks 20.03
 * Date: 21.10.2021
*/



/* HEADERS */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "pcap.h"



/* CONSTANTS */

#define ETH_HDR_SIZE 14
#define MAC_ADD_SIZE 6
#define IP_ADD_SIZE 4
#define LLC_HDR_SIZE 3

//offsets from the start of the specific header
#define ARP_OP_OFFSET 6
#define ETH_TYPE_OFFSET 12
#define SNAP_ETH_TYPE_OFFSET 3
#define DEST_PORT_OFFSET 2
#define ARP_PTC_TYPE_OFFSET 2



/* DEFINED STRUCTURES */


/* HEADER STRUCTURES */

typedef struct eth_header{
    unsigned char dest_address[MAC_ADD_SIZE]; //destination MAC address
    unsigned char source_address[MAC_ADD_SIZE]; //source MAC address
    unsigned short eth_type; //ethertype|length
} ETH_HDR;

typedef struct udp_header{
    unsigned short source_port; //source port
    unsigned short dest_port; //destination port
    unsigned short len; //length
    unsigned short checksum; //checksum
} UDP_HDR;

typedef struct arp_header{
    unsigned short hw_add_type; //hardware address type
    unsigned short ptc_add_type; //protocol address type
    unsigned char hw_add_len; //hardware address length
    unsigned char ptc_add_len; //protocol address length
    unsigned short operation; //operation
    unsigned char source_hw_add[MAC_ADD_SIZE]; //source hardware address
    unsigned char source_ptc_add[IP_ADD_SIZE]; //source protocol address
    unsigned char target_hw_add[MAC_ADD_SIZE]; //target hardware address
    unsigned char target_ptc_add[IP_ADD_SIZE]; //target protocol address
} ARP_HDR;

typedef struct icmp_header{
    unsigned char type; //type
    unsigned char code; //code
    unsigned short checksum; //checksum
} ICMP_HDR;

typedef struct ip_header{
    unsigned char version_and_ihl; //version and ihl
    unsigned char tos; //type of service
    unsigned short len; //total length
    unsigned short id; //identification
    unsigned short flags_and_offset; //flags and offset
    unsigned char ttl; //time to live
    unsigned char ptc; //protocol
    unsigned short checksum; //checksum
    unsigned char source_address[IP_ADD_SIZE]; //source address
    unsigned char dest_address[IP_ADD_SIZE]; //destination address
} IP_HDR;

typedef struct tcp_header{
    unsigned short source_port; //source port
    unsigned short dest_port; //destination port
    unsigned int sequence; //sequence
    unsigned int acknowledgement; //acknowledgement
    unsigned char offset; //offset and reserved
    unsigned char flags; //flags
    unsigned short window; //window
    unsigned short checksum; //checksum
    unsigned short urgent; //urgent pointer
} TCP_HDR;

typedef struct snap_header{
    unsigned char vendor_code[3]; //vendor code
    unsigned short eth_type; //ethertype
} SNAP_HDR;


/* COMMUNICATION STRUCTURES */

typedef struct tcp_communication{
    unsigned char host_a_ip[IP_ADD_SIZE]; //host a ip address
    unsigned char host_b_ip[IP_ADD_SIZE]; //host b ip address
    unsigned char handshake[3]; //3 way handshake - steps completed (0 = not completed, 1 = completed)
    unsigned char tear_down[4]; //tear down of communication - steps completed (0 = not completed, 1 = completed)
    unsigned short port; //source port
    int state; //state of communication: -1 = other, 0 = incomplete (only opened), 1 = complete
    int frames; //number of communication frames
    int *indexes; //frame numbers
} TCP_COMM;

typedef struct tftp_communication{
    unsigned char source_ip[IP_ADD_SIZE]; //source ip address
    unsigned char dest_ip[IP_ADD_SIZE]; //destination ip address
    unsigned short port; //source port
    unsigned short changed_port; //changed destination port
    int frames; //count of communication frames
    int *indexes; //frame numbers
} TFTP_COMM;

typedef struct icmp_communication{
    unsigned char source_ip[IP_ADD_SIZE]; //source ip address
    unsigned char dest_ip[IP_ADD_SIZE]; //destination ip address
    int state; //-1 = reply only
    int frames; //count of communication frames
    int *indexes; //frame numbers
} ICMP_COMM;

typedef struct arp_communication{
    unsigned char source_ip[IP_ADD_SIZE]; //source ip address
    unsigned char target_ip[IP_ADD_SIZE]; //target ip address
    unsigned char mac_address[MAC_ADD_SIZE]; //source mac address
    int state; //state of communication: 0 = request only, 1 = request and reply, -1 = reply only, 5 = ARP Probe, 6 = ARP Announcement, 7 = Gratuitous ARP
    int frames; //number of communication frames
    int *indexes; //frame numbers
} ARP_COMM;


/* STRUCTURES FOR STORING COMMUNICATIONS */
/* Containing all communications and their count */

typedef struct tcp_data{
    TCP_COMM **tcp_comm;
    int tcp_counter;
} TCP_DATA;

typedef struct tftp_data{
    TFTP_COMM **tftp_comm;
    int tftp_counter;
} TFTP_DATA;

typedef struct arp_data{
    ARP_COMM **arp_comm;
    int arp_counter;
} ARP_DATA;

typedef struct icmp_data{
    ICMP_COMM **icmp_comm;
    int icmp_counter;
} ICMP_DATA;


/* Storing IPV4 address statistic */
typedef struct ipv4_statistic{
    unsigned char source_ip[IP_ADD_SIZE]; //all source ipv4 address
    int packets_sent; //count of packets sent
} IPV4_STAT;

/*Storing IPV4 addresses statistics data*/
typedef struct ipv4_data{
    IPV4_STAT **ipv4_stat;
    int ipv4_counter;
} IPV4_DATA;



/* FUNCTIONS */


/* STRUCTURE INITIALIZING */

/* TCP communication */
TCP_COMM *init_tcp_comm(unsigned char *host_a_ip, unsigned char *host_b_ip, unsigned short port){
    TCP_COMM *tcp = (TCP_COMM *) malloc(sizeof(TCP_COMM));

    if(tcp)
        tcp->indexes = (int *) malloc(sizeof(int));
    if(!tcp || !tcp->indexes)
        return NULL;

    tcp->handshake[0] = 1; //first frame contains SYN - otherwise the initialization would not be called
    tcp->handshake[1] = 0;
    tcp->handshake[2] = 0;
    tcp->tear_down[0] = 0;
    tcp->tear_down[1] = 0;
    tcp->tear_down[2] = 0;
    tcp->tear_down[3] = 0;
    tcp->indexes[0] = 0;
    tcp->state = -1; //state -1 = other
    tcp->frames = 1; //contains the first frame
    tcp->port = port;
    memcpy(tcp->host_a_ip, host_a_ip, IP_ADD_SIZE);
    memcpy(tcp->host_b_ip, host_b_ip, IP_ADD_SIZE);

    return tcp;
}

/* TFTP communication */
TFTP_COMM *init_tftp_comm(unsigned char *source_ip, unsigned char *dest_ip, unsigned short port){
    TFTP_COMM *tftp = (TFTP_COMM *) malloc(sizeof(TFTP_COMM));

    if(tftp)
        tftp->indexes = (int *) malloc(sizeof(int));
    if(!tftp || !tftp->indexes)
        return NULL;
    if(!tftp){
        printf("Memory allocation error\n");
        return NULL;
    }

    memcpy(tftp->source_ip, source_ip, IP_ADD_SIZE);
    memcpy(tftp->dest_ip, dest_ip, IP_ADD_SIZE);
    tftp->indexes[0] = 0;
    tftp->port = port; //source port
    tftp->changed_port = 0; //destination port - will be changed after the second frame is encountered
    tftp->frames = 1; //contains the first frame

    return tftp;
}

/* ICMP communication */
ICMP_COMM *init_icmp_comm(unsigned char *source_ip, unsigned char *dest_ip){
    ICMP_COMM *icmp = (ICMP_COMM *) malloc(sizeof(ICMP_COMM));

    if(icmp)
        icmp->indexes = (int *) malloc(sizeof(int));
    if(!icmp || !icmp->indexes){
        printf("Memory allocation error\n");
        return NULL;
    }

    memcpy(icmp->source_ip, source_ip, IP_ADD_SIZE);
    memcpy(icmp->dest_ip, dest_ip, IP_ADD_SIZE);
    icmp->frames = 1; //contains the first frame

    return icmp;
}

/* ARP communication */
ARP_COMM *init_arp_comm(unsigned char *source_ip, unsigned char *target_ip, unsigned char *mac_address, unsigned short operation){
    ARP_COMM *arp = (ARP_COMM *) malloc(sizeof(ARP_COMM));
    unsigned char sender_probe_ip[4];

    for(int i = 0; i < IP_ADD_SIZE; i++)
        sender_probe_ip[i] = 0;

    if(arp)
        arp->indexes = (int *) malloc(sizeof(int));
    if(!arp || !arp->indexes){
        printf("Memory allocation error\n");
        return NULL;
    }

    if(operation == 1){ //request
        if(!(memcmp(source_ip, sender_probe_ip, IP_ADD_SIZE))) //ARP Probe - state = 5
            arp->state = 5;
        else if(!(memcmp(source_ip, target_ip, IP_ADD_SIZE))) //ARP Announcement - state = 6
            arp->state = 6;
        else //normal request - state = 0
            arp->state = 0;
    }
    else{
        if(!(memcmp(source_ip, target_ip, IP_ADD_SIZE))) //Gratuitous ARP - state = 7
            arp->state = 7;
        else //first frame contains normal reply - state = -1
            arp->state = -1;
    }

    arp->frames = 1; //contains the first frame
    memcpy(arp->source_ip, source_ip, IP_ADD_SIZE);
    memcpy(arp->target_ip, target_ip, IP_ADD_SIZE);
    memcpy(arp->mac_address, mac_address, MAC_ADD_SIZE);

    return arp;
};

/* TCP communications data */
TCP_DATA *init_tcp_data(void){
    TCP_DATA *tcp_data = (TCP_DATA *) malloc(sizeof(TCP_DATA));
    if(!tcp_data){
        printf("Memory allocation error\n");
        return NULL;
    }
    tcp_data->tcp_comm = NULL;
    tcp_data->tcp_counter = 0;
    return tcp_data;
}

/* TFTP communications data */
TFTP_DATA *init_tftp_data(void){
    TFTP_DATA *tftp_data = (TFTP_DATA *) malloc(sizeof(TFTP_DATA));
    if(!tftp_data){
        printf("Memory allocation error\n");
        return NULL;
    }
    tftp_data->tftp_comm = NULL;
    tftp_data->tftp_counter = 0;
    return tftp_data;
}

/* ICMP communications data */
ICMP_DATA *init_icmp_data(void){
    ICMP_DATA *icmp_data = (ICMP_DATA *) malloc(sizeof(ICMP_DATA));
    if(!icmp_data){
        printf("Memory allocation error\n");
        return NULL;
    }
    icmp_data->icmp_comm = NULL;
    icmp_data->icmp_counter = 0;
    return icmp_data;
}

/* ARP communications data */
ARP_DATA *init_arp_data(void){
    ARP_DATA *arp_data = (ARP_DATA *) malloc(sizeof(ARP_DATA));
    if(!arp_data){
        printf("Memory allocation error\n");
        return NULL;
    }
    arp_data->arp_comm = NULL;
    arp_data->arp_counter = 0;
    return arp_data;
}

/* IPV4 address statistic */
IPV4_STAT *init_ipv4_stat(unsigned char *source_ip){
    IPV4_STAT *ipv4 = (IPV4_STAT *) malloc(sizeof(IPV4_STAT));
    if(!ipv4)
        return NULL;
    memcpy(ipv4->source_ip, source_ip, IP_ADD_SIZE);
    ipv4->packets_sent = 1; //first packet already sent
    return ipv4;
}

/* IPV4 addresses statistics data */
IPV4_DATA *init_ipv4_data(void){
    IPV4_DATA *ipv4_data = (IPV4_DATA *) malloc(sizeof(IPV4_DATA));
    if(!ipv4_data){
        printf("Memory allocation error\n");
        return NULL;
    }
    ipv4_data->ipv4_stat = NULL;
    ipv4_data->ipv4_counter = 0;
    return ipv4_data;
}


/* GETTING SPECIFIC VALUE */

/* Extracting a specific bit and returning the value */

unsigned char extract_fin_bit(unsigned char value){
    return value & 0b00000001;
}

unsigned char extract_syn_bit(unsigned char value){
    return value & 0b00000010;
}

unsigned char extract_rst_bit(unsigned char value){
    return value & 0b00000100;
}

unsigned char extract_psh_bit(unsigned char value){
    return value & 0b00001000;
}

unsigned char extract_ack_bit(unsigned char value){
    return value & 0b00010000;
}

unsigned char extract_urg_bit(unsigned char value){
    return value & 0b00100000;
}

/* Returning the IP header length in bytes */
unsigned char get_ihl(unsigned char version_and_ihl){
    return (version_and_ihl & 0xF)*4;
}

/* Swapping bytes */
unsigned short swap_bytes(unsigned short value){
    return ((value >> 8) | ((value & 0xFF) << 8));
}


/* PRINTING DATA */

/* Printing MAC addresses */
void print_mac_adresses(unsigned char *source_address, unsigned char *dest_address, FILE *output){
    fprintf(output, "|———— Source MAC address: ");
    for(int i = 0; i < MAC_ADD_SIZE; i++)
        fprintf(output, "%.2X ", *(source_address + i));
    fprintf(output, "\n|———— Destination MAC address: ");
    for(int i = 0; i < MAC_ADD_SIZE; i++)
        fprintf(output, "%.2X ", *(dest_address + i));
    fprintf(output, "\n");
}

/* Printing IP addresses */
void print_ip_adresses(unsigned char *source_address, unsigned char *dest_address, FILE *output){
    fprintf(output, "|———— Source IP address: %d.%d.%d.%d\n", source_address[0], source_address[1], source_address[2], source_address[3]);
    fprintf(output, "|———— Destination IP address: %d.%d.%d.%d\n", dest_address[0], dest_address[1], dest_address[2], dest_address[3]);
}

/* Printing packet */
void print_packet(unsigned char *pkt_header, unsigned short pkt_len, FILE *output){
    fprintf(output, "| Packet:\n  ");
    for(unsigned short i= 0; i < pkt_len; i++){
        if(i % 16 == 0 && i != 0) //one line only contains 16 bytes
            fprintf(output, "\n  %.2X ", *(pkt_header + i));
        else if(i % 8 == 0 && i != 0) //first and second 8 bytes are separated by a space
            fprintf(output, " %.2X ", *(pkt_header + i));
        else
            fprintf(output, "%.2X ", *(pkt_header + i));
    }
    fprintf(output, "\n——————————————————————————————————————————————————\n\n");
}

/* Printing Ethernet standard */
void choose_eth_standard(unsigned short eth_type, unsigned char ieee_type, FILE *output){
    //checking eth_type/length first
    if(eth_type > 0x05DC) //ETHERNET II
        fprintf(output, "|—— Ethernet II\n");
    //IEEE 802.3 - checking ieee_type (LSAP)
    else if(ieee_type == 0xFF) //RAW
        fprintf(output, "|—— Novel 802.3 RAW\n");
    else if(ieee_type == 0xAA) //LLC + SNAP
        fprintf(output, "|—— IEEE 802.3 LLC + SNAP\n");
    else //LLC
        fprintf(output, "|—— IEEE 802.3 LLC\n");
}

/* Printing length */
void print_len(int len, FILE *output){
    fprintf(output, "| API length: %d\n", len); //print API length
    if(len < 60) //if API length is < 60, the wire length will always be 64
        fprintf(output, "| Wire length: %d\n", 64);
    else //else the wire length is going to be the API length + 4
        fprintf(output, "| Wire length: %d\n", len + 4);
}

/* Printing protocol|type */
int print_protocol(FILE *file, unsigned short value, FILE *output){
    unsigned short temp = 0; //value from the file
    int c = '\0'; //characters from file
    bool ptc_found = 0; //return value (protocol found?)

    rewind(file);

    while(1){
        fscanf(file, "%hX", &temp);
        if(temp == value){ //comparing values
            fprintf(output,"|—— ");
            getc(file);
            while((c = getc(file)) != '\n' && c != EOF){
                fprintf(output, "%c", c);
                ptc_found = 1;
            }

        }
        else //moving to next line
            while((c = getc(file)) != '\n' && c != EOF);
        if(c == EOF)
            break;
    }

    if(ptc_found)
        fprintf(output, "\n");

    return ptc_found;
}

/* Printing IPV4 statistics */
void print_ipv4_stats(IPV4_DATA *ipv4_data, FILE *output){
    int ipv4_counter = ipv4_data->ipv4_counter, most_pkt = 0; //most packets sent by an address
    IPV4_STAT *ipv4_stat; //temp

    fprintf(output, "==================================================================================================\n");
    fprintf(output, "\t\t\t\tIPV4 STATISTICS\n");
    fprintf(output, "==================================================================================================\n\n");
    fprintf(output, "Source addresses - [packets sent]:\n");

    //sorting IPs
    for(int i = 0; i < ipv4_counter; i++){
        for(int j = i + 1; j < ipv4_counter; j++){
            if(ipv4_data->ipv4_stat[i]->packets_sent < ipv4_data->ipv4_stat[j]->packets_sent){
                ipv4_stat = ipv4_data->ipv4_stat[i];
                ipv4_data->ipv4_stat[i] = ipv4_data->ipv4_stat[j];
                ipv4_data->ipv4_stat[j] = ipv4_stat;
            }
        }
    }

    //printing all addresses and finding the value of most packets sent by an address
    for(int i = 0; i < ipv4_counter; i++){
        ipv4_stat = ipv4_data->ipv4_stat[i];
        fprintf(output, "%d.%d.%d.%d - [%d]\n", ipv4_stat->source_ip[0], ipv4_stat->source_ip[1], ipv4_stat->source_ip[2], ipv4_stat->source_ip[3], ipv4_stat->packets_sent);
        if(most_pkt < ipv4_stat->packets_sent)
            most_pkt = ipv4_stat->packets_sent;
    }

    //printing addresses that sent the most packets
    fprintf(output, "\nMost packets sent:\n");
    for(int i = 0; i < ipv4_counter; i++){
        ipv4_stat = ipv4_data->ipv4_stat[i];
        if(ipv4_stat->packets_sent == most_pkt)
            fprintf(output, "%d.%d.%d.%d - [%d]\n", ipv4_stat->source_ip[0], ipv4_stat->source_ip[1], ipv4_stat->source_ip[2], ipv4_stat->source_ip[3], most_pkt);
    }
}

/* Printing TCP flags */
void print_tcp_flags(unsigned char flags, FILE *output){
    fprintf(output, "|———— Flags: ");
    if(extract_fin_bit(flags) == 1) //FIN
        fprintf(output, "[FIN]");
    if(extract_syn_bit(flags) == 2) //SYN
        fprintf(output, "[SYN]");
    if(extract_rst_bit(flags) == 4) //RST
        fprintf(output, "[RST]");
    if(extract_psh_bit(flags) == 8) //PSH
        fprintf(output, "[PSH]");
    if(extract_ack_bit(flags) == 16) //ACK
        fprintf(output, "[ACK]");
    if(extract_urg_bit(flags) == 32) //URG
        fprintf(output, "[URG]");
    fprintf(output, "\n");
}


/* OPENING AND CLOSING FILES */

/* Opening PCAP file */
pcap_t *open_pcap_file(char *file_name){
    char errbuf[PCAP_ERRBUF_SIZE]; //error buffer
    pcap_t *pcap_file = pcap_open_offline(file_name, errbuf);

    if(!pcap_file)
        printf("PCAP file opening error\n");

    return pcap_file;
}

/* Closing all files */
void close_files(pcap_t *pcap_ptr, FILE *files[6], FILE *output){
    for(int i = 0; i < 6; i++){
        if(files[i])
            fclose(files[i]);
    }
    if(pcap_ptr)
        pcap_close(pcap_ptr);
    if(output){
        fclose(output);
    }
}


/* FRAME ANALYSIS */

/* Making an analysis and printing data or returning specific value for communications to identify the frame */
/* Since TFTP is harder to identify, the function gets the boolean value tftp as an argument that was based on previous analysis */
int process_frame(const unsigned char *packet,struct pcap_pkthdr *pkt_hdr, int frame_counter, FILE *files[6], FILE *output, bool tftp, bool print){
    ETH_HDR *eth_hdr = (ETH_HDR *) packet;
    unsigned short eth_type = swap_bytes(eth_hdr->eth_type);
    unsigned char ieee_type = *((unsigned char *) eth_hdr + ETH_HDR_SIZE);
    int frame_type = 0;

    if(print){
        fprintf(output, ">> Frame #%d\n\n", frame_counter);
        print_len(pkt_hdr->len, output);
        choose_eth_standard(eth_hdr->eth_type, ieee_type, output);
        print_mac_adresses(eth_hdr->source_address, eth_hdr->dest_address, output);
    }

    if(eth_type > 0x05DC){ //Ethernet II
        if(print)
            print_protocol(files[0], eth_type, output);

        if(eth_type == 0x0800){ //IPV4
            IP_HDR *ip_hdr = (IP_HDR *) (packet + ETH_HDR_SIZE);

            if(print){
                print_ip_adresses(ip_hdr->source_address, ip_hdr->dest_address, output);
                print_protocol(files[1], ip_hdr->ptc, output);
            }

            if(ip_hdr->ptc == 0x0006){ //TCP
                TCP_HDR *tcp_hdr = (TCP_HDR *) (packet + ETH_HDR_SIZE + get_ihl(ip_hdr->version_and_ihl)); //getting the IHL to find out where the TCP header starts
                unsigned short source_port = swap_bytes(tcp_hdr->source_port);
                unsigned short dest_port = swap_bytes(tcp_hdr->dest_port);
                unsigned short tcp_port = source_port < dest_port ? source_port : dest_port;

                if(print){
                    print_tcp_flags(tcp_hdr->flags, output);
                    fprintf(output, "|———— Source port: %hu \n|———— Destination port: %hu\n", source_port, dest_port);
                    print_protocol(files[3], tcp_port, output);
                }

                frame_type = 'T'; //return value to identify TCP frame
            }
            else if(ip_hdr->ptc == 0x0011){ //UDP
                UDP_HDR *udp_hdr = (UDP_HDR *) (packet + ETH_HDR_SIZE + get_ihl(ip_hdr->version_and_ihl)); //getting the IHL to find out where the UDP header starts
                unsigned short source_port = swap_bytes(udp_hdr->source_port);
                unsigned short dest_port = swap_bytes(udp_hdr->dest_port);
                unsigned short ucp_port = source_port < dest_port ? source_port : dest_port;

                if(print){
                    fprintf(output, "|———— Source port: %hu \n|———— Destination port: %hu\n", source_port, dest_port);

                    if(tftp) //printing TFTP only when tftp boolean value is set
                        fprintf(output, "|—— TFTP\n");
                    else
                        print_protocol(files[4], ucp_port, output);
                }

                frame_type = 'U'; //return value to identify UDP frame
            }
            else if(ip_hdr->ptc == 0x0001){ //ICMP
                ICMP_HDR *icmp_hdr = (ICMP_HDR *) (packet + ETH_HDR_SIZE + get_ihl(ip_hdr->version_and_ihl)); //get the ip header length to find out where the icmp header starts

                if(print)
                    print_protocol(files[5], icmp_hdr->type, output); //print the icmp type

                frame_type = 'I'; //return value to identify ICMP frame
            }
            else
                frame_type = '4'; //return value to identify other IPV4 frames
        }
        else if(eth_type == 0x0806){ //ARP
            ARP_HDR *arp_hdr = (ARP_HDR *) (packet + ETH_HDR_SIZE);
            unsigned short ptc_add_type = swap_bytes(arp_hdr->ptc_add_type);
            unsigned short operation = swap_bytes(arp_hdr->operation);

            if(print){
                if(operation == 1){ //operation = 1 - REQUEST, printing IP for which the MAC address is to be found
                    unsigned char arp_probe_sender_ip[4]; //ARP Probe sender IP - 0.0.0.0

                    for(int i = 0; i < 4; i++)
                        arp_probe_sender_ip[i] = 0;

                    //source IP = ARP Probe sender IP, operation = REQUEST --> ARP PROBE
                    if(!(memcmp(arp_hdr->source_ptc_add, arp_probe_sender_ip, IP_ADD_SIZE)))
                        fprintf(output, "|———— Probe\n");
                    //source IP = target IP, operation = REQUEST --> ARP Announcement
                    else if(!(memcmp(arp_hdr->source_ptc_add, arp_hdr->target_ptc_add, IP_ADD_SIZE)))
                        fprintf(output, "|———— Announcement\n");

                    fprintf(output, "|———— OP: Request, ");
                    fprintf(output, "IP: %d.%d.%d.%d, ", arp_hdr->target_ptc_add[0], arp_hdr->target_ptc_add[1], arp_hdr->target_ptc_add[2], arp_hdr->target_ptc_add[3]);
                    fprintf(output, "MAC: ???\n");
                }
                else if(operation == 2){ //operation == 2 - REPLY, printing IP for which the MAC address was found
                    //source IP = target IP, operation = REPLY --> Gratuitous ARP
                    if(!(memcmp(arp_hdr->source_ptc_add, arp_hdr->target_ptc_add, IP_ADD_SIZE)))
                        fprintf(output, "|———— Gratuitous\n");

                    fprintf(output, "|———— OP: Reply, ");
                    fprintf(output, "IP: %d.%d.%d.%d, MAC: ", arp_hdr->source_ptc_add[0], arp_hdr->source_ptc_add[1], arp_hdr->source_ptc_add[2], arp_hdr->source_ptc_add[3]);

                    for(int i = 0; i < MAC_ADD_SIZE; i++)
                        fprintf(output, "%.2X ", *(arp_hdr->source_hw_add + i));

                    fprintf(output, "\n");
                }
                print_protocol(files[0], ptc_add_type, output);
                print_ip_adresses(arp_hdr->source_ptc_add, arp_hdr->target_ptc_add, output);
            }
            frame_type = 'A'; //return value to identify ARP frame
        }
    }
    else if(ieee_type == 0xAA && print){ //IEEE 802.3 LLC + SNAP
        SNAP_HDR *snap_hdr = (SNAP_HDR *) (packet + ETH_HDR_SIZE + LLC_HDR_SIZE);
        unsigned short eth_type = swap_bytes(snap_hdr->eth_type);
        print_protocol(files[0], eth_type, output);
    }
    else if(ieee_type == 0xFF && print) //IEEE 802.3 RAW - IPX protocol only
        fprintf(output, "|—— IPX\n");
    else if(print) //IEEE 802.3 LLC
        print_protocol(files[2], *(((unsigned char *) eth_hdr + ETH_HDR_SIZE)), output);

    if(print)
        print_packet((unsigned char *) eth_hdr, pkt_hdr->len, output);

    return frame_type;
}


/* CLASSIFYING FRAME INTO COMMUNICATIONS */

/* TCP communications insert */
TCP_DATA *tcp_insert(TCP_DATA *tcp_data, const unsigned char *packet, unsigned short port_id, int frame_counter, bool *error){
    IP_HDR *ip_hdr = (IP_HDR *) (packet + ETH_HDR_SIZE);
    TCP_HDR *tcp_hdr = (TCP_HDR *) (packet + ETH_HDR_SIZE + get_ihl(ip_hdr->version_and_ihl)); //geting the IHL to find out where the TCP header starts
    unsigned short source_port = swap_bytes(tcp_hdr->source_port);
    unsigned short dest_port = swap_bytes(tcp_hdr->dest_port);
    unsigned short port = source_port < dest_port ? dest_port : source_port; //source port of the first frame
    unsigned short tcp_port = source_port < dest_port ? source_port : dest_port; //destination port of the first frame
    bool processed = 0; //is frame a part of existing communication?
    TCP_COMM *tcp_comm = NULL; //temp

    if(port_id != tcp_port) //exit if TCP protocols are different
        return tcp_data;

    if(!tcp_data){ //initializing structure if it was not previously initialized
        if(!(tcp_data = init_tcp_data())){
            *error = 1;
            return NULL;
        }
    }

    //looping through all communications to classify the frame
    for(int i = 0; i < tcp_data->tcp_counter; i++){
        tcp_comm = tcp_data->tcp_comm[i];

        //host A = source address, host B = destination address, source ports are the same
        if(!(memcmp(tcp_comm->host_a_ip, ip_hdr->source_address, IP_ADD_SIZE)) && !(memcmp(tcp_comm->host_b_ip, ip_hdr->dest_address, IP_ADD_SIZE)) && tcp_comm->port == port){

            //host A might have sent the FIN flag to start the termination
            if(extract_fin_bit(tcp_hdr->flags) == 1 && tcp_comm->state == 0){
                tcp_comm->tear_down[0] = 1; //first step from host A done
                processed = 1;
            }

            //host B might have sent the FIN to start the termination - checking ACK from host A
            else if(extract_ack_bit(tcp_hdr->flags) == 16 && tcp_comm->tear_down[2] == 1 && tcp_comm->state == 0){
                tcp_comm->tear_down[3] = 1; //second step from host A done

                //host A might have sent the FIN to start the termination, checking ACK from host B
                if(tcp_comm->tear_down[0] == 1 && tcp_comm->tear_down[1] == 1)
                    tcp_comm->state = 2; //state = 2 - complete communication with no more frames
                processed = 1;
            }

            //host A might have sent the RST to terminate the communication
            else if(extract_rst_bit(tcp_hdr->flags) == 4 && tcp_comm->state == 0){
                tcp_comm->tear_down[0] = -1; //special RST step from host A = -1
                tcp_comm->state = 1; //state = 1 - complete communication with possible ACK frame
                processed = 1;
            }

            //host B might have sent the RST to terminate the communication, checking possible ACK from host A
            else if(extract_ack_bit(tcp_hdr->flags) == 16 && tcp_comm->tear_down[2] == -1 && tcp_comm->state != 2){
                tcp_comm->state = 2; //state = 2 - complete communication with no more frames
                processed = 1;
            }

            //host B might have completed the second step for opening communication (SYN,ACK), checking ACK from host A
            else if(extract_ack_bit(tcp_hdr->flags) == 16 && tcp_comm->handshake[1] == 1 && tcp_comm->state == -1){
                tcp_comm->handshake[2] = 1; //all steps done
                tcp_comm->state = 0; //state = 0 - opened communication
                processed = 1;
            }

            //regular frame, communication has to be opened
            else if(tcp_comm->state == 0)
                processed = 1;
        }

        //host B = source address, host A = destination address, source port = destination port
        else if(!(memcmp(tcp_comm->host_b_ip, ip_hdr->source_address, IP_ADD_SIZE)) && !(memcmp(tcp_comm->host_a_ip, ip_hdr->dest_address, IP_ADD_SIZE)) && tcp_comm->port == port){

            //host B might have completed his step to open communication (SYN,ACK)
            if(extract_syn_bit(tcp_hdr->flags) == 2 && extract_ack_bit(tcp_hdr->flags) == 16 && tcp_comm->state == -1){
                tcp_comm->handshake[1] = 1; //second step done
                processed = 1;
            }

            //host B might have sent the FIN to start the termination
            else if(extract_fin_bit(tcp_hdr->flags) == 1 && tcp_comm->state == 0){
                tcp_comm->tear_down[2] = 1; //first step from host B done
                processed = 1;
            }

            //host A might have started the termination, checking ACK from host B
            else if(extract_ack_bit(tcp_hdr->flags) == 16 && tcp_comm->tear_down[0] == 1 && tcp_comm->state == 0){
                tcp_comm->tear_down[1] = 1; //second step from host B done

                //host B might have sent the FIN flag to start the termination, checking ACK from host A
                if(tcp_comm->tear_down[2] == 1 && tcp_comm->tear_down[3] == 1)
                    tcp_comm->state = 2; //state 2 = complete communication with no more frames
                processed = 1;
            }

            //host B might have sent the RST to terminate the communication
            else if(extract_rst_bit(tcp_hdr->flags) == 4 && tcp_comm->state == 0){
                tcp_comm->tear_down[2] = -1; //special RST step from host B = -1
                tcp_comm->state = 1; //state = 1 - complete communication with possible ACK frame
                processed = 1;
            }

            //host A might have sent the RST to terminate the communication, checking possible ACK from host B
            else if(extract_ack_bit(tcp_hdr->flags) == 16 && tcp_comm->tear_down[0] == -1 && tcp_comm->state != 2){
                tcp_comm->state = 2; //state = 2 - complete communication with no more frames
                processed = 1;
            }

            //regular frame, communication has to be opened
            else if(tcp_comm->state == 0)
                processed = 1;
        }
        if(processed)
            break;
    }

    if(processed){ //inserting frame into existing communication
        tcp_comm->indexes = realloc(tcp_comm->indexes, sizeof(int) * (tcp_comm->frames + 1));

        if(!tcp_comm->indexes){
            for(int i = 0; i < tcp_data->tcp_counter; i++){
                free(tcp_data->tcp_comm[i]->indexes);
                free(tcp_data->tcp_comm[i]);
            }
            free(tcp_data->tcp_comm);
            free(tcp_data);
            *error = 1;
            printf("Memory allocation error\n");
            return NULL;
        }
        tcp_comm->indexes[tcp_comm->frames] = frame_counter;
        tcp_comm->frames++;
    }

    if(!processed && tcp_hdr->flags == 2){ //checking SYN frame and creating a new communication
        tcp_data->tcp_comm = realloc(tcp_data->tcp_comm, sizeof(TCP_COMM *) * (tcp_data->tcp_counter + 1));

        if(tcp_data->tcp_comm)
            tcp_data->tcp_comm[tcp_data->tcp_counter] = init_tcp_comm(ip_hdr->source_address, ip_hdr->dest_address, port);
        else{
            free(tcp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        if(!tcp_data->tcp_comm[tcp_data->tcp_counter]){
            for(int i = 0; i < tcp_data->tcp_counter; i++){
                free(tcp_data->tcp_comm[i]->indexes);
                free(tcp_data->tcp_comm[i]);
            }
            free(tcp_data->tcp_comm);
            free(tcp_data);
            printf("Memory allocation error.\n");
            *error = 1;
            return NULL;
        }
        tcp_data->tcp_comm[tcp_data->tcp_counter]->indexes[0] = frame_counter;
        tcp_data->tcp_counter++;
    }

    return tcp_data;
}

/*TFTP communications insert */
TFTP_DATA *tftp_insert(TFTP_DATA *tftp_data, const unsigned char *packet, int frame_counter){
    IP_HDR *ip_hdr = (IP_HDR *) (packet + ETH_HDR_SIZE);
    UDP_HDR *udp_hdr = (UDP_HDR *) (packet + ETH_HDR_SIZE + get_ihl(ip_hdr->version_and_ihl)); //get the IHL to find out where the UDP header starts
    unsigned short source_port = swap_bytes(udp_hdr->source_port);
    unsigned short dest_port = swap_bytes(udp_hdr->dest_port);
    bool processed = 0; //is frame a part of existing communication?
    TFTP_COMM *tftp_comm = NULL; //temp

    if(!tftp_data){ //initializing structure if it was not previously initialized
        if(!(tftp_data = init_tftp_data()))
            return NULL;
    }

    //destination port = 69 - starting frame of a new TFTP communication - creating one
    if(dest_port == 69){
        tftp_data->tftp_comm = realloc(tftp_data->tftp_comm, sizeof(TFTP_COMM *) * (tftp_data->tftp_counter + 1));

        if(tftp_data->tftp_comm)
            tftp_data->tftp_comm[tftp_data->tftp_counter] = init_tftp_comm(ip_hdr->source_address, ip_hdr->dest_address, source_port);
        else{
            free(tftp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        if(!tftp_data->tftp_comm[tftp_data->tftp_counter]){
            for(int i = 0; i < tftp_data->tftp_counter; i++){
                free(tftp_data->tftp_comm[i]->indexes);
                free(tftp_data->tftp_comm[i]);
            }
            free(tftp_comm);
            free(tftp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        tftp_data->tftp_comm[tftp_data->tftp_counter]->indexes[0] = frame_counter;
        tftp_data->tftp_counter++;

        return tftp_data;
    }

    //looping through all communications to classify the frame
    for(int i = 0; i < tftp_data->tftp_counter; i++){
        tftp_comm = tftp_data->tftp_comm[i];

        //source IP = primary source IP, destination IP = primary destination IP, source port = primary source port, destination port = primary destination port
        if(!(memcmp(tftp_comm->source_ip, ip_hdr->source_address, IP_ADD_SIZE)) && !(memcmp(tftp_comm->dest_ip, ip_hdr->dest_address, IP_ADD_SIZE))){
            if(tftp_comm->port == source_port && tftp_comm->changed_port == dest_port){
                processed = 1;
                break;
            }
        }
        //primary source IP = destination IP, primary destination IP = source IP
        else if((!memcmp(tftp_comm->dest_ip, ip_hdr->source_address, IP_ADD_SIZE)) && !(memcmp(tftp_comm->source_ip, ip_hdr->dest_address, IP_ADD_SIZE))){

            //communication contains 1 frame - change the primary destination port
            if(tftp_comm->frames == 1 && tftp_comm->port == dest_port){
                tftp_comm->changed_port = source_port;
                processed = 1;
                break;
            }

            //source port = changed destination port, destination port = primary source port
            else if(tftp_comm->frames > 1 && tftp_comm->changed_port == source_port && tftp_comm->port == dest_port){
                processed = 1;
                break;
            }
        }
    }

    if(processed){ //inserting frame into existing communication
        tftp_comm->indexes = realloc(tftp_comm->indexes, sizeof(int) * (tftp_comm->frames + 1));

        if(!tftp_comm->indexes){
            for(int i = 0; i < tftp_data->tftp_counter; i++){
                free(tftp_data->tftp_comm[i]->indexes);
                free(tftp_data->tftp_comm[i]);
            }
            free(tftp_data->tftp_comm);
            free(tftp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        tftp_comm->indexes[tftp_comm->frames] = frame_counter;
        tftp_comm->frames++;
    }

    return tftp_data;
}

/* ICMP communications insert */
ICMP_DATA *icmp_insert(ICMP_DATA *icmp_data, const unsigned char *packet, int frame_counter){
    IP_HDR *ip_hdr = (IP_HDR *) (packet + ETH_HDR_SIZE);
    ICMP_COMM *icmp_comm = NULL; //temp
    bool processed = 0; //is frame a part of existing communication?

    if(!icmp_data){ //initializing structure if it was not previously initialized
        if(!(icmp_data = init_icmp_data()))
            return NULL;
    }

    //looping through all communications to classify the frame
    for(int i = 0; i < icmp_data->icmp_counter; i++){
        icmp_comm = icmp_data->icmp_comm[i];

        //source IP = primary source IP, destination IP = primary destination ip
        if(!(memcmp(ip_hdr->source_address, icmp_comm->source_ip, IP_ADD_SIZE)) && !(memcmp(ip_hdr->dest_address, icmp_comm->dest_ip, IP_ADD_SIZE))){
            processed = 1;
            break;
        }

        //primary destination IP = source IP, primary source IP = destination IP
        else if(!(memcmp(ip_hdr->source_address, icmp_comm->dest_ip, IP_ADD_SIZE)) && !(memcmp(ip_hdr->dest_address, icmp_comm->source_ip, IP_ADD_SIZE))){
            processed = 1;
            break;
        }
    }

    if(processed){ //inserting frame into existing communication
        icmp_comm->indexes = realloc(icmp_comm->indexes, sizeof(int) * (icmp_comm->frames + 1));

        if(!icmp_comm->indexes){
            for(int i = 0; i < icmp_data->icmp_counter; i++){
                free(icmp_data->icmp_comm[i]->indexes);
                free(icmp_data->icmp_comm[i]);
            }
            free(icmp_data->icmp_comm);
            free(icmp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        icmp_comm->indexes[icmp_comm->frames] = frame_counter;
        icmp_comm->frames++;
    }
    else{ //creating a new communication
        icmp_data->icmp_comm = realloc(icmp_data->icmp_comm, sizeof(ICMP_COMM *) * (icmp_data->icmp_counter + 1));

        if(icmp_data->icmp_comm)
            icmp_data->icmp_comm[icmp_data->icmp_counter] = init_icmp_comm(ip_hdr->source_address, ip_hdr->dest_address);
        else{
            free(icmp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        if(!icmp_data->icmp_comm[icmp_data->icmp_counter]){
            for(int i = 0; i < icmp_data->icmp_counter; i++){
                free(icmp_data->icmp_comm[i]->indexes);
                free(icmp_data->icmp_comm[i]);
            }
            free(icmp_data->icmp_comm);
            free(icmp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        icmp_data->icmp_comm[icmp_data->icmp_counter]->indexes[0] = frame_counter;
        icmp_data->icmp_counter++;
    }

    return icmp_data;
}

/* ARP communications insert */
ARP_DATA *arp_insert(ARP_DATA *arp_data, const unsigned char *packet, int frame_counter){
    ARP_HDR *arp_hdr = (ARP_HDR *) (packet + ETH_HDR_SIZE);
    unsigned short operation = swap_bytes(arp_hdr->operation);
    ARP_COMM *arp_comm = NULL; //temp
    bool processed = 0; //is frame a part of existing communication?

    if(!arp_data){ //initializing structure if it was not previously initialized
        if(!(arp_data = init_arp_data()))
            return NULL;
    }

    //looping through all communications to classify the frame
    for(int i = 0; i < arp_data->arp_counter; i++){
        arp_comm = arp_data->arp_comm[i];

        //source IP = primary source IP, target IP = primary target IP, source MAC address = primary source MAC address, operation = REQUEST --> another REQUEST
        if(!(memcmp(arp_comm->source_ip, arp_hdr->source_ptc_add, IP_ADD_SIZE)) && !(memcmp(arp_comm->target_ip, arp_hdr->target_ptc_add, IP_ADD_SIZE))){
            if(!(memcmp(arp_comm->mac_address, arp_hdr->source_hw_add, MAC_ADD_SIZE)) && operation == 1){
                if(arp_comm->state == 0 || arp_comm->state == 5 || arp_comm->state == 6 || arp_comm->state == 7){ //normal request, Probe, Announcement, Gratuitous
                    processed = 1;
                    break;
                }
            }
        }

        //source IP = primary target IP, target IP = primary source IP, target MAC address = primary source MAC address, operation = REPLY --> ARP REPLY
        else if(!(memcmp(arp_comm->source_ip, arp_hdr->target_ptc_add, IP_ADD_SIZE)) && !(memcmp(arp_comm->target_ip, arp_hdr->source_ptc_add, IP_ADD_SIZE))){
            if((!memcmp(arp_comm->mac_address, arp_hdr->target_hw_add, MAC_ADD_SIZE)) && operation == 2){
                processed = 1;
                arp_comm->state = 1; //state = 1 - REQUEST + REPLY
                break;
            }
        }
    }

    if(processed){ //inserting frame into existing communications
        arp_comm->indexes = realloc(arp_comm->indexes, sizeof(int) * (arp_comm->frames + 1));

        if(!arp_comm->indexes){
            for(int i = 0; i < arp_data->arp_counter; i++){
                free(arp_data->arp_comm[i]->indexes);
                free(arp_data->arp_comm[i]);
            }
            free(arp_data->arp_comm);
            free(arp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        arp_comm->indexes[arp_comm->frames] = frame_counter;
        arp_comm->frames++;
    }
    else{ //creating a new communication
        arp_data->arp_comm = realloc(arp_data->arp_comm, sizeof(ARP_COMM *) * (arp_data->arp_counter + 1));

        if(arp_data->arp_comm)
            arp_data->arp_comm[arp_data->arp_counter] = init_arp_comm(arp_hdr->source_ptc_add, arp_hdr->target_ptc_add, arp_hdr->source_hw_add, operation);
        else{
            free(arp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        if(!arp_data->arp_comm[arp_data->arp_counter]){
            for(int i = 0; i < arp_data->arp_counter; i++){
                free(arp_data->arp_comm[i]->indexes);
                free(arp_data->arp_comm[i]);
            }
            free(arp_data->arp_comm);
            free(arp_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        arp_data->arp_comm[arp_data->arp_counter]->indexes[0] = frame_counter;
        arp_data->arp_counter++;
    }

    return arp_data;
}

/* IPV4 address insert */
IPV4_DATA *ipv4_insert(IPV4_DATA *ipv4_data, const unsigned char *packet){
    IP_HDR *ip_hdr = (IP_HDR *) (packet + ETH_HDR_SIZE);
    bool present = 0; //is source IP already recorded?

    if(!ipv4_data){ //initializing structure if it was not previously initialized
        if(!(ipv4_data = init_ipv4_data()))
            return NULL;
    }

    //looping through all communications to find a match
    for(int i = 0; i < ipv4_data->ipv4_counter; i++){

        //comparing source IPs
        if(!(memcmp(ip_hdr->source_address, ipv4_data->ipv4_stat[i]->source_ip, IP_ADD_SIZE))){
            ipv4_data->ipv4_stat[i]->packets_sent++; //incrementing the number of packets sent
            present = 1;
            break;
        }
    }

    if(!present){ //inserting new source IP
        ipv4_data->ipv4_stat = realloc(ipv4_data->ipv4_stat, sizeof(IPV4_STAT *) * (ipv4_data->ipv4_counter + 1));

        if(ipv4_data->ipv4_stat)
            ipv4_data->ipv4_stat[ipv4_data->ipv4_counter] = init_ipv4_stat(ip_hdr->source_address);
        else{
            printf("Memory allocation error\n");
            free(ipv4_data);
            return NULL;
        }
        if(!ipv4_data->ipv4_stat[ipv4_data->ipv4_counter]){
            for(int i = 0; i < ipv4_data->ipv4_counter; i++)
                free(ipv4_data->ipv4_stat[i]);
            free(ipv4_data->ipv4_stat);
            free(ipv4_data);
            printf("Memory allocation error\n");
            return NULL;
        }
        ipv4_data->ipv4_counter++; //increment the ipv4 addresses counter
    }

    return ipv4_data;
}


/* MAIN FUNCTION */

int main(int args, char *argv[]){
    char pcap_file_name[30]; //PCAP file name input
    const unsigned char *packet; //packet pointer
    struct pcap_pkthdr *pkt_header; //packet header pointer
    pcap_t *pcap_ptr; //pcap file pointer
    FILE *files[6]; //files = pointer to an array of pointers to files

    //opening input files
    files[0] = fopen("input/eth_types.txt", "r"); //Ether Types
    files[1] = fopen("input/ip_protocols.txt", "r"); //IP Protocols
    files[2] = fopen("input/llc_saps.txt", "r"); //LLC SAPS
    files[3] = fopen("input/tcp_ports.txt", "r"); //TCP Ports
    files[4] = fopen("input/udp_ports.txt", "r"); //UDP Ports
    files[5] = fopen("input/icmp_types.txt", "r"); //ICMP Types

    for(int i = 0; i < 6; i++){
        if(!files[i]){
            printf(">>> Input files opening error.\n");
            close_files(NULL, files, NULL);
            return -1;
        }
    }

    printf("====================================================\n\n");
    printf("\t   NETWORK COMMUNICATION ANALYZER\n\n");
    printf("====================================================\n\n");
    memcpy(pcap_file_name, "input/", 6);

    //getting input PCAP file name
    while(1){
        printf("\nName of the PCAP file: ");
        scanf("%s", pcap_file_name + 6);
        if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
            printf("\nType '0' to exit or anything else to try again: ");
            fflush(stdin);
            if(getchar() == '0'){
                close_files(pcap_ptr, files, NULL);
                return 0;
            }
            fflush(stdin);
        }
        else{
            pcap_close(pcap_ptr); pcap_ptr = NULL;
            break;
        }
    }
    printf("\n");


    while(1){
        int option = 0, frame_counter = 1; //chosen option, frame number counter
        char output_file_name[30]; //output file name
        FILE *output = NULL; //output file pointer

        //printing all the options available
        printf("Choose one of analysis options:\n");
        printf("1: Complete analysis according to points 1-3\n");
        printf("2: HTTP\n");
        printf("3: HTTPS\n");
        printf("4: TELNET\n");
        printf("5: SSH\n");
        printf("6: FTP-CONTROL\n");
        printf("7: FTP-DATA\n");
        printf("8: TFTP\n");
        printf("9: ICMP\n");
        printf("10: ARP\n");
        printf("11: EXIT\n\nSelect option: ");

        //getting the input option
        while(scanf("%d", &option) != 1 || option < 1 || option > 11){
            fflush(stdin);
            printf("Invalid option\n\nSelect option: ");
        }

        if(option == 11){ //EXIT -> close files and free memory
            close_files(NULL, files, NULL);
            return 0;
        }
        else{ //getting the input file name and opening
            memcpy(output_file_name, "output/", 7);
            while(1){
                printf("Name of the output file: "); //file name scan
                scanf("%s", output_file_name + 7);
                if(!(output = fopen(output_file_name, "w"))){ //open file and check for error
                    fflush(stdin);
                    printf("Output file opening error\n\nType '0' to exit or anything else to try again: ");
                    if(getchar() == '0'){
                        close_files(NULL, files, NULL);
                        return 0;
                    }
                    fflush(stdin);
                    printf("\n");
                }
                else
                    break;
            }
            printf("\n");
        }

        //complete analysis according to points 1-3
        if(option == 1){
            TFTP_DATA *tftp_data = NULL; //TFTP communications data
            IPV4_DATA *ipv4_data = NULL; //IPV4 statistics

            if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
                close_files(NULL, files, output);
                return -1;
            }

            //first cycle serves for gathering TFTP communications data, does not print anything
            while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                int frame_type = process_frame(packet, pkt_header, frame_counter, files, output, 0, 0);
                if(frame_type == 'U'){
                    if(!(tftp_data = tftp_insert(tftp_data, packet, frame_counter))){
                        close_files(pcap_ptr, files, output);
                        return -1;
                    }
                }
                frame_counter++;
            }
            pcap_close(pcap_ptr); pcap_ptr = NULL;
            frame_counter = 1;

            if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
                close_files(NULL, files, output);
                return -1;
            }

            //second cycle serves for frame analysis printing and gathering IPV4 statistics
            while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                bool tftp = 0;

                if(tftp_data){
                    //nested cycle to check whether the frame is not a part of TFTP communication
                    for(int i = 0; i < tftp_data->tftp_counter; i++){
                        for(int j = 0; j < tftp_data->tftp_comm[i]->frames; j++){
                            if(tftp_data->tftp_comm[i]->indexes[j] == frame_counter)
                                tftp = 1;
                        }
                    }
                }
                //printing frame and saving the return value
                int frame_type = process_frame(packet, pkt_header, frame_counter, files, output, tftp, 1);

                //IPV4 frame - insert into statistics
                if(frame_type == 'T' || frame_type == 'U' || frame_type == 'I' || frame_type == '4'){
                    if(!(ipv4_data = ipv4_insert(ipv4_data, packet))){
                        close_files(pcap_ptr, files, output);
                        return -1;
                    }
                }
                frame_counter++;
            }
            //printing IPV4 statistics and freeing memory
            if(ipv4_data){
                print_ipv4_stats(ipv4_data, output);
                for(int i = 0; i < ipv4_data->ipv4_counter; i++)
                    free(ipv4_data->ipv4_stat[i]);
                free(ipv4_data->ipv4_stat);
                free(ipv4_data);
            }
            if(tftp_data){
                for(int i = 0; i < tftp_data->tftp_counter; i++){
                    free(tftp_data->tftp_comm[i]->indexes);
                    free(tftp_data->tftp_comm[i]);
                }
                free(tftp_data->tftp_comm);
                free(tftp_data);
            }
            pcap_close(pcap_ptr); pcap_ptr = NULL;
        }

        //TCP communications analysis
        else if(option >= 2 && option <= 7){
            TCP_DATA *tcp_data = NULL;
            unsigned short tcp_port = 0;
            bool error = 0; //did error occurred when inserting TCP frame?

            switch(option){ //switch option to set the destination port
                case 2: //HTTP
                    tcp_port = 0x0050;
                    break;
                case 3: //HTTPS
                    tcp_port = 0x01BB;
                    break;
                case 4: //TELNET
                    tcp_port = 0x0017;
                    break;
                case 5: //SSH
                    tcp_port = 0x0016;
                    break;
                case 6: //FTP-CONTROL
                    tcp_port = 0x0015;
                    break;
                case 7: //FTP-DATA
                    tcp_port = 0x0014;
                    break;
                default: break;
            }

            if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
                close_files(NULL, files, output);
                return -1;
            }

            //first cycle serves to gather information about the specific TCP communications
            while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                int frame_type = process_frame(packet, pkt_header, frame_counter, files, output, 0, 0);

                if(frame_type == 'T'){ //inserting TCP frame
                    tcp_data = tcp_insert(tcp_data, packet, tcp_port, frame_counter, &error);

                    if(error){
                        close_files(pcap_ptr, files, output);
                        return -1;
                    }
                }
                frame_counter++;
            }
            pcap_close(pcap_ptr); pcap_ptr = NULL;

            if(!tcp_data){ //no communications found
                fprintf(output, "==================================================================================================\n\n");
                fprintf(output, "\t\t\t\tTHERE ARE NO COMMUNICATIONS\n\n");
                fprintf(output, "==================================================================================================\n\n\n");
                fclose(output);
                continue;
            }

            //complete, incomplete = temp variables to find out if we have both complete and incomplete communication of this type
            int complete = 0, incomplete = 0;
            TCP_COMM *tcp_temp, *complete_tcp = NULL, *incomplete_tcp = NULL; //temp pointers

            //looping through all communications to find the first complete and incomplete communication
            for(int i = 0; i < tcp_data->tcp_counter; i++){
                tcp_temp = tcp_data->tcp_comm[i];

                if(tcp_temp->state == 0 && incomplete == 0){ //incomplete communication found
                    incomplete_tcp = tcp_temp; //save the pointer
                    incomplete = 1; //set variable to 1 - found
                }
                else if((tcp_temp->state == 1 || tcp_temp->state == 2) && complete == 0){ //complete communication found
                    complete_tcp = tcp_temp; //save the pointer
                    complete = 1; //set variable to 1 - found
                }

                if(complete && incomplete) //if both of the communication were found break the loop
                    break;
            }

            if(!complete && !incomplete){ //there are some communications, but none of them are complete or incomplete
                for(int i = 0; i < tcp_data->tcp_counter; i++){
                    free(tcp_data->tcp_comm[i]->indexes);
                    free(tcp_data->tcp_comm[i]);
                }
                free(tcp_data->tcp_comm);
                free(tcp_data);
                fprintf(output, "==================================================================================================\n\n");
                fprintf(output, "\t\t\tTHERE ARE NO COMPLETE/INCOMPLETE COMMUNICATIONS\n\n");
                fprintf(output, "==================================================================================================\n\n\n");
                fclose(output);
                continue;
            }
            else if(!complete){ //no complete communication
                fprintf(output, "==================================================================================================\n\n");
                fprintf(output, "\t\t\tTHERE ARE NO COMPLETE COMMUNICATIONS\n\n");
                fprintf(output, "==================================================================================================\n\n\n");
            }
            else if(!incomplete){ //no incomplete communication
                fprintf(output, "==================================================================================================\n\n");
                fprintf(output, "\t\t\tTHERE ARE NO INCOMPLETE COMMUNICATIONS\n\n");
                fprintf(output, "==================================================================================================\n\n\n");
            }

            //analyzing the whole PCAP file again for each communication (if both exist)
            for(int i = 0; i < (complete + incomplete); i++){
                if(complete_tcp){ //first printed is going to be the complete communication
                    tcp_temp = complete_tcp;
                    complete_tcp = NULL;
                }
                else if(incomplete_tcp){ //incomplete communication is going to be printed as second
                    tcp_temp = incomplete_tcp;
                    incomplete_tcp = NULL;
                }

                if(tcp_temp->state == 1 || tcp_temp->state == 2){ //based on state print the communication type
                    fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n");
                    fprintf(output, "\t\t\t\tFIRST COMPLETE COMMUNICATION\n");
                    fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n\n");
                }
                else if(tcp_temp->state == 0){
                    fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n");
                    fprintf(output, "\t\t\t\tFIRST INCOMPLETE COMMUNICATION\n");
                    fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n\n");
                }

                if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
                    close_files(NULL, files, output);
                    return -1;
                }

                int communication_frame_counter = frame_counter = 1; //number of communication frames proccessed

                //cycle to print the communication frames
                while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                    if(tcp_temp->frames < communication_frame_counter) //break cycle if all frames of communication were processed
                        break;
                    //print only the first and last 10 frames of communication, check if frame numbers are the same - print
                    else if(communication_frame_counter < 11 || communication_frame_counter > (tcp_temp->frames - 10)){
                        if(tcp_temp->indexes[communication_frame_counter - 1] == frame_counter)
                            process_frame(packet, pkt_header, frame_counter, files, output, 0, 1);
                    }
                    //increment the number of communication frames processed if frame numbers are the same
                    if(tcp_temp->indexes[communication_frame_counter - 1] == frame_counter)
                        communication_frame_counter++;

                    frame_counter++;
                }
                pcap_close(pcap_ptr); pcap_ptr = NULL;
                fprintf(output, "\n");
            }
            //freeing memory
            for(int i = 0; i < tcp_data->tcp_counter; i++){
                free(tcp_data->tcp_comm[i]->indexes);
                free(tcp_data->tcp_comm[i]);
            }
            free(tcp_data->tcp_comm);
            free(tcp_data);
        }

        //TFTP communications analysis
        else if(option == 8){
            TFTP_DATA *tftp_data = NULL;

            if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
                close_files(NULL, files, output);
                return -1;
            }

            //first cycle serves to gather information about the TFTP communications
            while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                int frame_type = process_frame(packet, pkt_header, frame_counter, files, output, 0, 0);

                if(frame_type == 'U'){ //inserting frame
                    if(!(tftp_data = tftp_insert(tftp_data, packet, frame_counter))){
                        close_files(pcap_ptr, files, output);
                        return -1;
                    }
                }
                frame_counter++;
            }
            pcap_close(pcap_ptr); pcap_ptr = NULL;

            //UDP frames with unknown protocol were encountered but none of them was a part of TFTP communication
            if(!tftp_data || !tftp_data->tftp_counter){
                fprintf(output, "==================================================================================================\n\n");
                fprintf(output, "\t\t\t\tTHERE ARE NO TFTP COMMUNICATIONS\n\n");
                fprintf(output, "==================================================================================================\n\n\n");
                if(tftp_data && !tftp_data->tftp_counter)
                    free(tftp_data);
                fclose(output);
                continue;
            }

            //analyzing the whole PCAP file again for each communication
            for(int i = 0; i < tftp_data->tftp_counter; i++){
                TFTP_COMM *tftp_temp = tftp_data->tftp_comm[i]; //temp variable
                int communication_frame_counter = frame_counter = 1; //number of communication frames processed


                if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
                    close_files(NULL, files, output);
                    return -1;
                }

                fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n");
                fprintf(output, "\t\t\t\t\tCOMMUNICATION %d\n", i + 1);
                fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n\n");

                //cycle to print the communication frames
                while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                    if(tftp_temp->frames < communication_frame_counter) //break cycle if all frames of communication were processed
                        break;
                    //print only the first and last 10 frames of communication, check if frame numbers are the same - print
                    else if(communication_frame_counter < 11 || communication_frame_counter > (tftp_temp->frames - 10)){
                        if(tftp_temp->indexes[communication_frame_counter - 1] == frame_counter)
                            process_frame(packet, pkt_header, frame_counter, files, output, 1, 1);
                    }
                    //increment the number of communication frames processed if frame numbers are the same
                    if(tftp_temp->indexes[communication_frame_counter - 1] == frame_counter)
                        communication_frame_counter++;

                    frame_counter++;
                }
                pcap_close(pcap_ptr); pcap_ptr = NULL;
                fprintf(output, "\n");
            }
            //freeing memory
            for(int i = 0; i < tftp_data->tftp_counter; i++){
                free(tftp_data->tftp_comm[i]->indexes);
                free(tftp_data->tftp_comm[i]);
            }
            free(tftp_data->tftp_comm);
            free(tftp_data);
        }

        //ICMP communications analysis
        else if(option == 9){ //ICMP parsing
            ICMP_DATA *icmp_data = NULL;

            if(!(pcap_ptr = open_pcap_file(pcap_file_name))){ //check whether file was opened correctly
                close_files(NULL, files, output);
                return -1;
            }

            //first cycle serves to gather information about the ICMP communications
            while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                int frame_type = process_frame(packet, pkt_header, frame_counter, files, output, 0, 0);
                if(frame_type == 'I'){
                    if(!(icmp_data = icmp_insert(icmp_data, packet, frame_counter))){
                        close_files(pcap_ptr, files, output);
                        return -1;
                    }
                }
                frame_counter++;
            }
            pcap_close(pcap_ptr); pcap_ptr = NULL;

            if(!icmp_data){ //no communications found
                fprintf(output, "==================================================================================================\n\n");
                fprintf(output, "\t\t\t\tTHERE ARE NO ICMP COMMUNICATIONS\n\n");
                fprintf(output, "==================================================================================================\n\n\n");
                fclose(output);
                continue;
            }

            //analyzing the whole PCAP file again for each communication
            for(int i = 0; i < icmp_data->icmp_counter; i++){
                ICMP_COMM *icmp_temp = icmp_data->icmp_comm[i]; //temp
                int communication_frame_counter = frame_counter = 1; //number of communication frames processed

                if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
                    close_files(NULL, files, output);
                    return -1;
                }

                fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n");
                fprintf(output, "\t\t\t\t\tCOMMUNICATION %d\n", i + 1);
                fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n\n");

                //cycle to print the communication frames
                while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                    if(icmp_temp->frames < communication_frame_counter) //break cycle if all frames of communication were processed
                        break;
                    //print only the first and last 10 frames of communication, check if frame numbers are the same - print
                    else if(communication_frame_counter < 11 || communication_frame_counter > (icmp_temp->frames - 10)){
                        if(icmp_temp->indexes[communication_frame_counter - 1] == frame_counter)
                            process_frame(packet, pkt_header, frame_counter, files, output, 0, 1);
                    }
                    //increment the number of communication frames processed if frame numbers are the same
                    if(icmp_temp->indexes[communication_frame_counter - 1] == frame_counter)
                        communication_frame_counter++;
                    frame_counter++;
                }
                pcap_close(pcap_ptr); pcap_ptr = NULL;
                fprintf(output, "\n");
            }
            //freeing memory
            for(int i = 0; i < icmp_data->icmp_counter; i++){
                free(icmp_data->icmp_comm[i]->indexes);
                free(icmp_data->icmp_comm[i]);
            }
            free(icmp_data->icmp_comm);
            free(icmp_data);
        }

        //ARP communications analysis
        else if(option == 10){
            ARP_DATA *arp_data = NULL;

            if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
                close_files(NULL, files, output);
                return -1;
            }

            //first cycle serves to gather information about the ARP communications
            while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                int frame_type = process_frame(packet, pkt_header, frame_counter, files, output, 0, 0);
                if(frame_type == 'A'){
                    if(!(arp_data = arp_insert(arp_data, packet, frame_counter))){
                        close_files(pcap_ptr, files, output);
                        return -1;
                    }
                }
                frame_counter++;
            }
            pcap_close(pcap_ptr); pcap_ptr = NULL;

            if(!arp_data){ //no communications found
                fprintf(output, "==================================================================================================\n\n");
                fprintf(output, "\t\t\t\tTHERE ARE NO ARP COMMUNICATIONS\n\n");
                fprintf(output, "==================================================================================================\n\n\n");
                fclose(output);
                continue;
            }

            int communication_counter = 0; //counter for
            int request_reply = 0, request = 0, reply = 0, probe = 0, announcement = 0, gratuitous = 0; //number of communications for each type
            bool neg_state_print = 1, state0_print = 1, state1_print = 1, state5_print = 1, state6_print = 1, state7_print = 1; //bool for printing a type of communication

            //cycle to count number of communications for each type
            for(int i = 0; i < arp_data->arp_counter; i++){
                switch(arp_data->arp_comm[i]->state){
                    case -1:
                        reply++;
                        break;
                    case 0:
                        request++;
                        break;
                    case 1:
                        request_reply++;
                        break;
                    case 5:
                        probe++;
                        break;
                    case 6:
                        announcement++;
                        break;
                    case 7:
                        gratuitous++;
                        break;
                    default:
                        break;
                }
            }

            //analyzing the whole PCAP file again for each type of ARP communication
            for(int i = 0; i < arp_data->arp_counter; i++){
                ARP_COMM *arp_temp = arp_data->arp_comm[i]; //temp
                int communication_frame_counter = frame_counter = 1; //number of communication frames processed
                /* this is a mess, but what it does is:
                 * 1. makes sure that the order of communications is: Request + Reply -> Request only -> Reply only -> ARP Probes -> ARP Announcements -> Gratuitous ARP
                 * 2. prints the type of communications that will follow
                 * 3. resets loop iterator when all of the communications of specific type are processed
                 * 4. resets communication counter after all the communications of specific type are processed
                */
                if(request_reply > 0){
                    if(arp_temp->state != 1)
                        continue;
                    else{
                        request_reply--;
                        communication_counter++;
                    }

                    if(state1_print){
                        state1_print = 0;
                        communication_counter = 1;
                        fprintf(output, "==================================================================================================\n\n");
                        fprintf(output, "\t\t\t\t\tREQUEST + REPLY\n\n");
                        fprintf(output, "==================================================================================================\n\n\n");
                    }
                }
                else if(request_reply == 0){
                    request_reply--;
                    i = -1;
                    continue;
                }
                else if(request > 0){
                    if(arp_temp->state != 0)
                        continue;
                    else{
                        request--;
                        communication_counter++;
                    }

                    if(state0_print){
                        state0_print = 0;
                        communication_counter = 1;
                        fprintf(output, "==================================================================================================\n\n");
                        fprintf(output, "\t\t\t\t\tREQUEST ONLY\n\n");
                        fprintf(output, "==================================================================================================\n\n\n");
                    }
                }
                else if(request == 0){
                    request--;
                    i = -1;
                    continue;
                }
                else if(reply > 0){
                    if(arp_temp->state != -1)
                        continue;
                    else{
                        reply--;
                        communication_counter++;
                    }

                    if(neg_state_print){
                        neg_state_print = 0;
                        communication_counter = 1;
                        fprintf(output, "==================================================================================================\n\n");
                        fprintf(output, "\t\t\t\t\tREPLY ONLY\n\n");
                        fprintf(output, "==================================================================================================\n\n\n");
                    }
                }
                else if(reply == 0){
                    reply--;
                    i = -1;
                    continue;
                }
                else if(probe > 0){
                    if(arp_temp->state != 5)
                        continue;
                    else{
                        probe--;
                        communication_counter++;
                    }

                    if(state5_print){
                        state5_print = 0;
                        communication_counter = 1;
                        fprintf(output, "==================================================================================================\n\n");
                        fprintf(output, "\t\t\t\t\tARP PROBE\n\n");
                        fprintf(output, "==================================================================================================\n\n\n");
                    }
                }
                else if(probe == 0){
                    probe--;
                    i = -1;
                    continue;
                }
                else if(announcement > 0){
                    if(arp_temp->state != 6)
                        continue;
                    else{
                        announcement--;
                        communication_counter++;
                    }

                    if(state6_print){
                        state6_print = 0;
                        communication_counter = 1;
                        fprintf(output, "==================================================================================================\n\n");
                        fprintf(output, "\t\t\t\t\tARP ANNOUNCEMENT\n\n");
                        fprintf(output, "==================================================================================================\n\n\n");
                    }
                }
                else if(announcement == 0){
                    announcement--;
                    i = -1;
                    continue;
                }
                else if(gratuitous > 0){
                    if(arp_temp->state != 7){
                        continue;
                    }
                    else{
                        gratuitous--;
                        communication_counter++;
                    }

                    if(state7_print){
                        state7_print = 0;
                        communication_counter = 1;
                        fprintf(output, "==================================================================================================\n\n");
                        fprintf(output, "\t\t\t\t\tGRATUITOUS ARP\n\n");
                        fprintf(output, "==================================================================================================\n\n\n");
                    }
                }
                else if(gratuitous == 0){
                    gratuitous--;
                    i = -1;
                    continue;
                }


                if(!(pcap_ptr = open_pcap_file(pcap_file_name))){
                    close_files(NULL, files, output);
                    return -1;
                }

                fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n");
                fprintf(output, "\t\t\t\t\tCOMMUNICATION %d\n", communication_counter);
                fprintf(output, "——————————————————————————————————————————————————————————————————————————————————————————————————\n\n");

                //cycle to print the communication frames
                while(pcap_next_ex(pcap_ptr, &pkt_header, &packet) >= 0){
                    if(arp_temp->frames < communication_frame_counter) //break cycle if all frames of communication were processed
                        break;
                    //print only the first and last 10 frames of communication, check if frame numbers are the same - print
                    else if(communication_frame_counter < 11 || communication_frame_counter > (arp_temp->frames - 10)){
                        if(arp_temp->indexes[communication_frame_counter - 1] == frame_counter)
                            process_frame(packet, pkt_header, frame_counter, files, output, 0, 1);
                    }
                    //increment the number of communication frames processed if frame numbers are the same
                    if(arp_temp->indexes[communication_frame_counter - 1] == frame_counter)
                        communication_frame_counter++;

                    frame_counter++;
                }
                pcap_close(pcap_ptr); pcap_ptr = NULL;
                fprintf(output, "\n");
            }
            //freeing memory
            for(int i = 0; i < arp_data->arp_counter; i++){
                free(arp_data->arp_comm[i]->indexes);
                free(arp_data->arp_comm[i]);
            }
            free(arp_data->arp_comm);
            free(arp_data);
        }
        fclose(output);
    }
}
