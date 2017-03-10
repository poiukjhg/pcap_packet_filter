
#ifdef MAKE_PACKET_H
#define MAKE_PACKET_H
unsigned short check_sum(unsigned short *addr, int len);
void make_packet_eth_head(const unsigned char* send_packet, const unsigned char* recv_packet);
void make_packet_ip_head(const unsigned char* send_packet, const unsigned char* recv_packet, int pay_load_len);
void make_packet_tcp_head(const unsigned char* send_packet, const unsigned char* recv_packet, int pay_load_len);
int make_packet_payload(const u_char* send_packet, const char* send_payload, int len);
void rebuild_checkum(const unsigned char* send_packet, int pay_load_len);
#endif