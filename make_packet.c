#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "packet_sys_cfg.h"
#include "packet_filter.h"
#include "make_packet.h"

/*const char http_redirect_header[] = 
    "HTTP/1.1 301 Moved Permanently\r\n"
    "Location: http://www.sina.com.cn\r\n"
    "Content-Type: text/html; charset=iso-8859-1\r\n"
    "Content-length: 0\r\n"
    "Cache-control: no-cache\r\n"
    "\r\n";
    */      
unsigned short check_sum(unsigned short *addr, int len){  
   register int nleft = len;  
   register int sum = 0;  
   register u_short *w = addr;  
   u_short answer = 0;  
  
   while(nleft > 1){  
       sum += *w++;  
       nleft -= 2;  
   }  
   if(nleft == 1){  
       *(u_char *)(&answer) = *(u_char *)w;  
       sum += answer;  
   }  
   sum = (sum >> 16) + (sum & 0xffff);  
   sum += (sum >> 16);  
   answer = ~sum;  
   return (answer);  
}  

void make_packet_eth_head(const u_char* send_packet, const u_char* recv_packet){
    int size_ethernet = sizeof(struct sniff_ethernet);
    struct sniff_ethernet* send_ethernet;
    struct sniff_ethernet* recv_ethernet;
    recv_ethernet = (struct sniff_ethernet*)(recv_packet);
    send_ethernet = (struct sniff_ethernet*)(send_packet);
    memcpy(send_ethernet->ether_dhost, recv_ethernet->ether_shost, ETHER_ADDR_LEN);
    memcpy(send_ethernet->ether_shost, recv_ethernet->ether_dhost, ETHER_ADDR_LEN);
    send_ethernet->ether_type = 0x0008;
    LOG("recv eth src addr: 0x"MAC_FMT, MACQUAD(recv_ethernet->ether_shost));
    LOG("recv eth dst addr: 0x"MAC_FMT, MACQUAD(recv_ethernet->ether_dhost));     
    LOG("send eth src addr: 0x"MAC_FMT, MACQUAD(send_ethernet->ether_shost));
    LOG("send eth dst addr: 0x"MAC_FMT, MACQUAD(send_ethernet->ether_dhost));   
    LOG("send eth type 0x%04x ", (u_int)(send_ethernet->ether_type));    
}
void make_packet_ip_head(const u_char* send_packet, const u_char* recv_packet, int pay_load_len){
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp); 
    struct sniff_ip* send_iph = (struct sniff_ip*)(send_packet + size_ethernet);   
    struct sniff_ip* recv_iph = (struct sniff_ip*)(recv_packet + size_ethernet);    
	send_iph->ip_vhlu.ip_vhl= recv_iph->ip_vhlu.ip_vhl;	
	send_iph->ip_tos = 0;
	send_iph->ip_len = htons(pay_load_len+size_tcp+size_ip);
	send_iph->ip_id = 0;
	send_iph->ip_off = htons(IP_DF);
	send_iph->ip_ttl = recv_iph->ip_ttl;
	send_iph->ip_p = IPPROTO_TCP;	
    send_iph->ip_src = recv_iph->ip_dst;
    send_iph->ip_dst = recv_iph->ip_src;
    send_iph->ip_sum = check_sum((short unsigned int *)send_iph, send_iph->ip_vhlu.ip_vhls.ip_hl);
    LOG("send ip ip_vhl 0x%02x ", send_iph->ip_vhlu.ip_vhl);
    LOG("send ip des ip " NIPQUAD_FMT, NIPQUAD(send_iph->ip_dst));
    LOG("send ip src ip " NIPQUAD_FMT, NIPQUAD(send_iph->ip_src));
    LOG("send ip check_sum %d", send_iph->ip_sum);           
}
void make_packet_tcp_head(const u_char* send_packet, const u_char* recv_packet, int pay_load_len){
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp);  
    struct sniff_tcp* send_tcph = (struct sniff_tcp*)(send_packet + size_ethernet + size_ip); 
    struct sniff_tcp* recv_tcph = (struct sniff_tcp*)(recv_packet + size_ethernet + size_ip);  
	send_tcph->th_off = size_tcp >> 2;
	send_tcph->th_sport = recv_tcph->th_dport;
	send_tcph->th_dport = recv_tcph->th_sport;    
	send_tcph->th_seq = recv_tcph->th_ack;
	send_tcph->th_ack = htonl(ntohl(recv_tcph->th_seq)+pay_load_len);	
	send_tcph->th_flags = 0x18;       
	send_tcph->th_win = recv_tcph->th_win;	
	send_tcph->th_sum = 0; //check_sum
    send_tcph->th_urp = 0;        
    LOG("recv tcp seq:%u ", ntohl(recv_tcph->th_seq));
    LOG("recv tcp ack:%u ", ntohl(recv_tcph->th_ack));    
    LOG("send tcp seq:%u ", ntohl(send_tcph->th_seq));
    LOG("send tcp ack:%u ", ntohl(send_tcph->th_ack));
    LOG("send tcp sport:%d ", ntohs(send_tcph->th_sport));
    LOG("send tcp dport:%d ", ntohs(send_tcph->th_dport));         
}
int make_packet_payload(const u_char* send_packet, const char* send_payload, int len){
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp);  
    u_char* payload = (u_char* )(send_packet + size_ethernet + size_ip + size_tcp);  
    memcpy(payload, send_payload, len);
    return len;
}
void rebuild_checkum(const u_char* send_packet, int pay_load_len){       
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp);  
    int size_psd = sizeof(struct p_tcp_header);
    struct sniff_tcp* send_tcph = (struct sniff_tcp*)(send_packet + size_ethernet + size_ip);
    struct sniff_ip* send_iph = (struct sniff_ip*)(send_packet + size_ethernet);
    struct p_tcp_header psd_header;
    psd_header.ip_dst = send_iph->ip_dst;
    psd_header.ip_src = send_iph->ip_src;
    psd_header.mbz = 0;
    psd_header.ptcl = 0x06;
    psd_header.tcpl = htons(pay_load_len+size_tcp);   
    u_char* buffer = (u_char*)malloc(pay_load_len+size_tcp+size_psd);   
    memcpy(buffer, &psd_header, size_psd);
    memcpy(buffer + size_psd, send_tcph, size_tcp); 
    send_tcph->th_sum = check_sum((short unsigned int *)buffer, size_psd+size_tcp);       
    free(buffer);
    LOG("send tcp check_sum %d", send_tcph->th_sum);      
}
