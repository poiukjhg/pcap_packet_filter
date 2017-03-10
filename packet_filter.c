#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "packet_sys_cfg.h"
#include "packet_filter.h"
#include "send_queue.h"
#include "make_packet.h"

const char HTTP_GET_STR[] = "GET";  
struct  send_package_queue * send_queue;
const char http_redirect_header[] = 
    "HTTP/1.1 302 Moved Temporarily\r\n"
    "Location: www.baidu.com\r\n"
    "\r\n";  
    
struct send_packet_and_len* make_redirect_packet(const u_char* packet){
    u_char* buffer = (char*)malloc(SNAP_LEN); 
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp);  
    int pay_load_len = 0;     
    if(buffer == NULL){
        LOG("malloc send buffer error");
        return NULL;
    }    
    memset(buffer, '0', SNAP_LEN);    
    struct send_packet_and_len* spl = (struct send_packet_and_len* )malloc(sizeof(struct send_packet_and_len ));
    if(spl == NULL){
        LOG("malloc send buffer struct error");
        free(buffer);
        return NULL;
    }
    spl->send_packet = buffer;
    spl->len = 0;      
    pay_load_len = make_packet_payload(buffer, http_redirect_header, strlen(http_redirect_header));
    spl->len += pay_load_len;     
    make_packet_tcp_head(buffer, packet, pay_load_len);
    spl->len += size_tcp;          
    make_packet_ip_head(buffer, packet, pay_load_len);
    spl->len += size_ip;
    make_packet_eth_head(buffer, packet);
    spl->len += size_ethernet;   
    rebuild_checkum(buffer, pay_load_len);     
    return  spl;          
}
 
struct send_packet_and_len* make_rst_packet(const u_char* packet){
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp);  
    int old_pay_load_len = 0; 
    struct sniff_ip* iph = (struct sniff_ip*)(packet + size_ethernet);
    struct sniff_tcp* tcph = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
    if (packet == NULL){
        LOG("rst packet error");
        return NULL;
    }        
    struct send_packet_and_len* spl = (struct send_packet_and_len* )malloc(sizeof(struct send_packet_and_len ));
    if(spl == NULL){
        LOG("malloc send buffer struct error");        
        return NULL;
    }
    old_pay_load_len = ntohs(iph->ip_len)- size_tcp-size_ip;
    iph->ip_len = htons(size_tcp+size_ip);
    tcph->th_ack = 0;//htonl(ntohl(recv_tcph->th_seq)-old_pay_load_len);
    tcph->th_flags = 0x04; 
    rebuild_checkum(packet, 0);  
    spl->send_packet =  packet;
    spl->len = size_ethernet + size_ip+size_tcp;  
    return  spl;          
}  

void send_pcap_packet(pcap_t* descr, const u_char* packet_len){
	struct send_packet_and_len* spl = NULL;
    u_char* send_packet;
    int i = 0;
    int len = 0;
    int send_len = 0;
    spl = (struct send_packet_and_len*)(packet_len);
    if(spl == NULL){
        LOG("send_packet_and_len is NULL");
        return;
    }
    send_packet = spl->send_packet;
    len = spl->len;
    LOG("send packet: len %d ", len);
    if((send_len = pcap_inject(descr, send_packet, len))<0){        
        pcap_perror(descr, "send packet error: ");
    }  
    LOG("send packet payload len %d:", send_len);
    /*
    for (i = 0; i < len; i++) {
        if(i%8 == 0)
            printf("\n\r");           
        if(send_packet[i] == 0)
            printf("00");
        else                     
            printf("%02x", send_packet[i]);  
                       
    }        
    printf("\n\r");
    */
    free(send_packet);
    free(spl);
    return;
}

void* send_packet_queue(){
    pcap_t* descr ;
    u_char* packet = NULL;
    u_char* node_data = NULL;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;     
    bpf_u_int32 maskp;         
    bpf_u_int32 netp;
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){ 
        ERR_EXIT(1, "%s\n", errbuf);
    }
    LOG("dev = %s", dev);            
    pcap_lookupnet(dev,&netp,&maskp,errbuf);   
    descr = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
    if(descr == NULL){ 
        ERR_EXIT(1, "pcap_open_live(): %s\n", errbuf);
    }    
    while(1){        
        node_data  = DeQueue(send_queue);
        if(node_data != NULL){                        
            LOG("DeQueue recv packet addr = %p", node_data);
            send_pcap_packet(descr, (const u_char* )(node_data));             
        }              
    }
    pcap_close(descr); 
}

void my_pcap_callback(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    static int count = 0;
    int i = 0;
    char* http_packet_start;
    u_char* recv_packet_copy = NULL;
    u_char* rst_packet_copy = NULL;
    const struct sniff_ethernet* ethernet; /* 以太网帧头部*/
    const struct sniff_ip* iph; /* IP包头部 */
    const struct sniff_tcp* tcph; /* TCP包头部 */
    struct sniff_tcp* rst_tcph; /* TCP包头部 */
    const char* payload; /* 数据包的有效载荷*/
    int size_ethernet = sizeof(struct sniff_ethernet);
    int size_ip = sizeof(struct sniff_ip);
    int size_tcp = sizeof(struct sniff_tcp);              
    struct send_packet_and_len* send_spl = NULL;
    struct send_packet_and_len* rst_spl = NULL;
    int send_rst_len;    
    ethernet = (struct sniff_ethernet*)(packet);
    iph = (struct sniff_ip*)(packet + size_ethernet);
    tcph = (struct sniff_tcp*)(packet + size_ethernet + size_ip);  
    if (ntohs(iph->ip_len)>(size_ip + size_tcp)){
        count++;  
        payload = (u_char *)(packet + size_ethernet + size_ip + size_tcp);
        if (strncasecmp(payload, HTTP_GET_STR, 3) == 0){
            /*
            LOG("Payload:");
            for (i = 0; i < pkthdr->len; i++) { 
                if(i%8 == 0)
                    printf("\n\r");                  
                if(packet[i] == 0)
                    printf("00");
                else                     
                    printf("%02x", packet[i]);                    
            }    
            printf("\n\r");
            LOG("get packet: %d", count);                
            LOG("Received Packet Size: %d, %d", pkthdr->len,  pkthdr->caplen);  
            LOG("eth src addr: 0x"MAC_FMT, MACQUAD(ethernet->ether_shost));
            LOG("eth dst addr: 0x"MAC_FMT, MACQUAD(ethernet->ether_dhost));
            LOG("des ip " NIPQUAD_FMT, NIPQUAD(iph->ip_dst));
            LOG("src ip " NIPQUAD_FMT, NIPQUAD(iph->ip_src));  
            LOG("ip len %d ", ntohs(iph->ip_len));
            LOG("src port:%d ", ntohs(tcph->th_sport));
            LOG("dst port:%d ", ntohs(tcph->th_dport));
            LOG("seq %u, ack:%u, flags:0x%02x", ntohl(tcph->th_seq), ntohl(tcph->th_ack), tcph->th_flags);                   
            LOG("http payload: ");    
            for(i = (size_ethernet + size_ip + size_tcp); i < pkthdr->len; i++){
                if (isprint(packet[i]))
                    printf("%c", packet[i]);
                else
                    printf("%2x", packet[i]);           
            } 
            printf("\n\r"); 
            */    
            LOG("seq %u, ack:%u, flags:0x%02x", ntohl(tcph->th_seq), ntohl(tcph->th_ack), tcph->th_flags);         
            LOG("handle get http packet");                        
                   
            //send rst packet   
            /*
            rst_packet_copy = (u_char*)malloc(pkthdr->caplen);
            if(rst_packet_copy == NULL){
                LOG("make rst error");
                goto out;
            }                
            memcpy(rst_packet_copy, packet, pkthdr->caplen);                    

            rst_spl = make_rst_packet(rst_packet_copy);
            if(rst_spl == NULL){
                LOG("make rst_spl error");
                goto out;
            }          
            if (EnQueue(send_queue, (void*)rst_spl)<0){                
                LOG("enqueue error");
                goto out;
            }
            */
            //LOG("rst packet seq %u, ack:%u, flags:0x%02x", ntohl(rst_tcph->th_seq), ntohl(rst_tcph->th_ack), rst_tcph->th_flags);
//send 302 packet   
            recv_packet_copy = (u_char*)malloc(pkthdr->caplen);
            if(recv_packet_copy == NULL){
                LOG("make recv_packet_copy error");
                goto out;
            }             
            memcpy(recv_packet_copy, packet, pkthdr->caplen);
            LOG("EnQueue recv source packet addr = %p", packet);
            LOG("EnQueue recv dup packet addr = %p", recv_packet_copy);
            LOG("make packet");
            send_spl = make_redirect_packet(recv_packet_copy);
            if(send_spl == NULL){
                LOG("make packet error");
                goto out;
            }            
            if (EnQueue(send_queue, (void*)send_spl)<0){
                LOG("enqueue error");
                goto out;
            }            

            //fflush(stdout);
            
            return;
out:
            if(rst_packet_copy != NULL){
                free(rst_packet_copy);
            }
            if(rst_spl != NULL){
                free(rst_spl);
            }
            if(recv_packet_copy != NULL){
                free(recv_packet_copy);
            } 
            if(send_spl != NULL){
                free(send_spl);
            }                                                 
            return;
        }        
    } 
}

int get_iplist_filter_str(int socket_r_fd, char* host_ip_filter_buffer, int buffer_len){
    ssize_t len = 0;
    LOG("get_iplist_filter_str");
    len = recv(socket_r_fd, host_ip_filter_buffer, buffer_len, 0);    
    if(len > 0){    
        LOG("read filter str: %s, len: %d ", host_ip_filter_buffer, (int)len);    
        return IP_LIST_CHANGED;
    }        
    return IP_LIST_NOT_CHANGED;
}
void* check_ip_filter_change(void* p_filter_patam){
    thread_filter_param*  filter_patam = (thread_filter_param*)p_filter_patam;
    while(1){
        LOG("check_ip_filter_change 1");
        memset(filter_patam->host_ip_filter_buffer, 0, IP_LIST_BUFFER_LEN);
        LOG("check_ip_filter_change 2");
        if(get_iplist_filter_str(filter_patam->socket_r_fd, filter_patam->host_ip_filter_buffer, IP_LIST_BUFFER_LEN) == IP_LIST_CHANGED){
            LOG("filter changed"); 
            LOG("new filter str to compile is %s", filter_patam->host_ip_filter_buffer);             
            pcap_breakloop(filter_patam->descr);
            LOG("break loop");
        }    
        sleep(120);
    }
}

int packet_filter(int socket_r_fd){
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;    
    struct ether_header *eptr; 
    struct bpf_program fp;     
    bpf_u_int32 maskp;         
    bpf_u_int32 netp;          
    char host_ip_filter[IP_LIST_BUFFER_LEN] = {'\0'};
    int res = 0;
    pthread_t thread_id_recv_filter;
    pthread_t thread_id_send_packet;  
    thread_filter_param filter_patam;
    
    send_queue = InitQueue();    
    if (send_queue == NULL){
        ERR_EXIT(1, "send queue init error\n");
    }          
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){ 
        ERR_EXIT(1, "%s\n", errbuf);
    }
    LOG("dev = %s", dev);    
    pcap_lookupnet(dev,&netp,&maskp,errbuf);   
    descr = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
    if(descr == NULL){ 
        ERR_EXIT(1, "pcap_open_live(): %s\n", errbuf);
    }
    filter_patam.socket_r_fd = socket_r_fd;
    filter_patam.host_ip_filter_buffer = host_ip_filter;
    filter_patam.descr = descr;
    res = pthread_create(&thread_id_recv_filter, NULL, &check_ip_filter_change, (void*)&filter_patam);
    if(res <0){
        perror("pthread_create recv filter error"); 
        pcap_close(descr);     
        exit(-1);
    }  
    res = pthread_create(&thread_id_send_packet, NULL, &send_packet_queue, NULL);
    if(res <0){
        perror("pthread_create send packet error"); 
        pcap_close(descr);    
        exit(-1);
    }      
          
    while(1){
            LOG("pcap loop start, filter str is %s", host_ip_filter);
            if(pcap_compile(descr, &fp, host_ip_filter, 0, netp) == -1){ 
                pcap_perror(descr, "Error calling pcap_compile");
                pcap_close(descr);
                ERR_EXIT(1, "Error calling pcap_compile\n"); 
            }
            LOG("start to install filter str: %s", host_ip_filter);
            if(pcap_setfilter(descr,&fp) == -1){
                pcap_close(descr);
                ERR_EXIT(1, "Error setting filter\n"); 
            } 
        LOG("start pcap_loop");     
        //res = pcap_dispatch(descr, 0, my_pcap_callback, NULL);
        //LOG("pcap_dispatch count : %d", res);
        res = pcap_loop(descr, -1, my_pcap_callback, (u_char* )descr);                
        if (res<0)
            pcap_perror(descr, "pcap_loop");      
    }
    pcap_close(descr); 
    return R_P_OK;
}