#ifndef CYCLE_GETIP_H 
#define CYCLE_GETIP_H
    
    typedef struct filter_ip_list_p{
        char ip_str[16];
        struct filter_ip_list_p* head;
        struct filter_ip_list_p* next;
    }filter_ip_list_p;
                
    void get_ip_loop(int socket_w_fd, char* check_host_filename);
#endif