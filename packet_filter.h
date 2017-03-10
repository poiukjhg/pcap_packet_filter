#include <pcap.h>
#include <netinet/if_ether.h>
#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H    
    #define NIPQUAD_FMT "%u.%u.%u.%u"
    #define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0],  ((unsigned char *)&addr)[1],  ((unsigned char *)&addr)[2],  ((unsigned char *)&addr)[3]

    #define MAC_FMT "%02x%02x%02x%02x%02x%02x"
    #define MACQUAD(addr) \
    ((unsigned char *)&addr)[0],  ((unsigned char *)&addr)[1],  ((unsigned char *)&addr)[2],  ((unsigned char *)&addr)[3], ((unsigned char *)&addr)[4], ((unsigned char *)&addr)[5]
    #define SNAP_LEN 1518 

    typedef struct thread_filter_param{
        int socket_r_fd;
        char* host_ip_filter_buffer;
        pcap_t* descr;        
    }thread_filter_param;
    
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };    
    /* IP header */
    struct sniff_ip {
        //u_char ip_vhl; /* version << 4 | header length >> 2 */
        
        union{
            u_char ip_vhl; // version << 4 | header length >> 2 
            struct{
                u_char ip_hl:4, // 头部长度
                ip_v:4; // 版本号 
            }ip_vhls;
        }ip_vhlu;
                      
        u_char ip_tos; /* type of service */
        u_short ip_len; /* total length */
        u_short ip_id; /* identification */
        u_short ip_off; /* fragment offset field */
        #define IP_RF 0x8000 /* reserved fragment flag */
        #define IP_DF 0x4000 /* dont fragment flag */
        #define IP_MF 0x2000 /* more fragments flag */
        #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
        u_char ip_ttl; /* time to live */
        u_char ip_p; /* protocol */
        u_short ip_sum; /* checksum */
        struct in_addr ip_src;
        struct in_addr ip_dst; /* source and dest address */
    }; 
    struct sniff_tcp {
        u_short th_sport; /* 源端口 */
        u_short th_dport; /* 目的端口 */
        u_int  th_seq; /* 包序号 */
        u_int  th_ack; /* 确认序号 */
        u_int th_x2:4, /* 还没有用到 */
        th_off:4; /* 数据偏移 */
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FINTH_SYNTH_RSTTH_ACKTH_URGTH_ECETH_CWR)
        u_short th_win; /* TCP滑动窗口 */
        u_short th_sum; /* 头部校验和 */
        u_short th_urp; /* 紧急服务位 */
    };  
    struct send_packet_and_len{
        u_char* send_packet;
        int len;
    };
    struct p_tcp_header
    {
        struct in_addr ip_src; // 源地址
        struct in_addr ip_dst; // 目的地址
        char mbz;// 置空
        char ptcl; // 协议类型
        unsigned short tcpl; //TCP 长度
    };    
    int packet_filter(int socket_r_fd);
#endif