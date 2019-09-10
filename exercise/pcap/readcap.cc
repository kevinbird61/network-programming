/**
 * Bitmap control program - execute mod1 only.
 * 
 * - use to evaluate the report rate of mod1 (e.g. influence of mod1).
 * - use flow-level to collect stats and inspect.
 */

#include <map>
#include <cmath>
#include <vector>
#include <iostream>

extern "C"
{
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "pcap_def.h"
}

// ethernet 
#define SIZE_ETHER 14
const struct sniff_ethernet *ethernet; // ethernet header
const struct sniff_ipv4 *ipv4; // IPv4 header
const struct sniff_tcp *tcp;   // TCP header
const struct sniff_udp *udp;   // UDP header
const struct sniff_icmp *icmp; // ICMP header
const char *payload; // packet payload
u_int size_existed=0;

using namespace std;

map<string, map<string, double>> ip_lastSeen;      // last seen of flow (timestamp)

double total_pkt=0, ipv4_pkt=0, ipv6_pkt=0, arp_pkt=0, other_pkt=0;

int upperbound=1000, use_long_term=1;
double long_term_timeout=50; // default to 50 sec

// packet process function
void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv){
    int ch,input_type=0,extract=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "df:u:t:")) != -1)
    {
        switch(ch)
        {
            case 't':
                // long-term timeout
                long_term_timeout=atof(optarg);
                break;
            case 'u':
                // upperbound
                upperbound=atoi(optarg);
                break;
            case 'd':
                debug=1;
                break;
            case 'f':
                optind--;
                for( ;optind < argc && *argv[optind] != '-'; optind++){
                    // push new file
                    inputfile.push_back(argv[optind]);
                }
                break;
        }
    }

    struct pcap_pkthdr header; 
    const u_char *packet;
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];

    for(int i=0;i<inputfile.size();i++){
        // cout << "Input file: " << inputfile.at(i) << endl;
        handle = pcap_open_offline(inputfile.at(i).c_str(), errbuf); 
        if (handle == NULL) { 
            fprintf(stderr, "Couldn't open pcap file: %s\n", inputfile.at(i).c_str()); 
            fprintf(stderr, "%s\n", errbuf);
            return(2); 
        }
        // run 
        pcap_loop(handle, 0, pkt_process, NULL);
        // close
        pcap_close(handle);
    }

    cout << "ARP ratio: " << arp_pkt / (float)total_pkt << endl;
    cout << "IPv4 ratio: " << ipv4_pkt / (float)total_pkt << endl;
    cout << "IPv6 ratio: " << ipv6_pkt / (float)total_pkt << endl;
    cout << "Other: " << other_pkt / (float)total_pkt << endl;

    return 0;
}

void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* ============================================= */
    /* Ethernet  */
    /* ============================================= */
    ethernet = (struct sniff_ethernet*)(packet);
    size_existed += SIZE_ETHER;

    total_pkt++;

    // Parse IPv4
    if(ntohs(ethernet->etherType) == ETHERTYPE_IP){
        ipv4_pkt++;

        ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
        u_int size_ip = IP_HL(ipv4)*4;
        size_existed += size_ip;

        // Step1: Get flow id
        string srcIP = string(inet_ntoa(ipv4->srcAddr));
        string dstIP = string(inet_ntoa(ipv4->dstAddr));
        // Step3: execute each module defined by bitmap - get lastSeen 
        double lastseen_ts, interval=0;
        if(ip_lastSeen[srcIP].find(dstIP)==ip_lastSeen[srcIP].end()){
            //lastSeen[srcIP][dstIP]=0;
            lastseen_ts = 0;
        } else {
            lastseen_ts=ip_lastSeen[srcIP][dstIP];
        }
        // interval
        interval = (header->ts.tv_sec + header->ts.tv_usec/1000.0) - lastseen_ts;

        // port 
        u_short srcPort=0, dstPort=0;

        if(size_ip < 20){
            printf("Invalid IPv4 header length: %u bytes\n", size_ip);
        } else {
            // Parse TCP 
            if(ipv4->protocol == (u_char)6){
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
                u_int size_tcp = TH_OFF(tcp)*4;
                size_existed += size_tcp;
                /* ============================================= */
                /* TCP              */
                /* ============================================= */
                srcPort=tcp->sport;
                dstPort=tcp->dport;

            } else if(ipv4->protocol == (u_char)17){
                udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                u_int size_udp = 8; // 8 bytes
                size_existed += size_udp;

                /* ============================================= */
                /* UDP              */
                /* ============================================= */
                srcPort=udp->sport;
                dstPort=udp->dport;
                // mod4[srcIP][dstIP].cnt++;
                
            } else if(ipv4->protocol == (u_char)1){
                /* ============================================= */
                /* ICMP              */
                /* ============================================= */
                icmp = (struct sniff_icmp*)(packet + SIZE_ETHER + size_ip);
                u_int size_icmp = 4; // 4 bytes
                size_existed += size_icmp;
            }

        }

        // update lastseen (Need to wait until all module has been finished)
        ip_lastSeen[srcIP][dstIP]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
    } else if(ntohs(ethernet->etherType) == ETHERTYPE_IPV6){ // IPv6
        ipv6_pkt++;
    } else if(ntohs(ethernet->etherType) == ETHERTYPE_ARP){
        arp_pkt++;
    } else {
        other_pkt++;
        // cout << std::hex << ntohs(ethernet->etherType) << endl;
    }
    /* ============================================= */
    /* Others (L2)  */
    /* ============================================= */
    payload = (char*)(packet + size_existed);
    size_existed = 0; // reset
}