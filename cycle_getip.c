#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "packet_sys_cfg.h"
#include "cycle_getip.h"

const char FILTER_BASE_STR[] = "tcp and dst port 80 and dst host ";

filter_ip_list_p* filter_ip_list_backup = NULL;
int get_iplist_in_file(char* file_name, char* ip_filter_str){
    FILE *fp;
    char* p = NULL;
    char buf[LINE] = {'\0'};
    char static first_line = 0;
    char ip_addr[16] = {'\0'};
    char* filter_p = ip_filter_str;
    
    struct addrinfo hints;
    struct addrinfo *addr_res, *addr_cur; 
    struct sockaddr_in *addr_p;
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    //Allow IPv4 or IPv6 
    hints.ai_socktype = SOCK_DGRAM; // Datagram socket 
    //hints.ai_socktype = SOCK_STREAM; 
    hints.ai_flags = AI_PASSIVE;    // For wildcard IP address 
    hints.ai_protocol = 0;          // Any protocol 
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    /*
    struct hostent *hptr;
    char* pptr;
    */
    if ((fp=fopen(file_name, "r")) == NULL) {
        ERR_EXIT(1, "open file %s error\n", file_name);
    }
    
    while(1) {
        first_line = 0;
        memset(buf, 0, LINE);
        p = fgets(buf, LINE, fp);
        if(!p){
            LOG("close file %s", file_name);
            fclose(fp);
            break;                
        }  
        buf[strlen(buf)-1]=0;        
        LOG("get host name: %s", buf);
        
        if (getaddrinfo(buf, NULL, &hints, &addr_res) == -1) {
            perror("getaddrinfo");            
        }
        if(addr_res == NULL){
            LOG("addr_res is NULL");
            continue;
        }
        for (addr_cur = addr_res; addr_cur != NULL; addr_cur = addr_cur->ai_next) {
            addr_p = (struct sockaddr_in *)addr_cur->ai_addr;
            memset(ip_addr, 0, 16);
            inet_ntop(AF_INET, &addr_p->sin_addr, ip_addr, 16);
            LOG("ip = %s", ip_addr);
            if (memcmp("0.0.0.0", ip_addr, strlen("0.0.0.0")-1)== 0)  {
                LOG("ignore this loop");
                continue;
            }                         
            if(first_line == 1){                                
                strncat(filter_p, " or ", 4);
                filter_p += 4;
                strncat(filter_p, ip_addr, strlen(ip_addr));
                filter_p += strlen(ip_addr);
                LOG("ip_filter_str line: %s", ip_filter_str);
            }  
            else if(first_line == 0){
                first_line = 1;
                strncat(filter_p, FILTER_BASE_STR, strlen(FILTER_BASE_STR));
                filter_p += strlen(FILTER_BASE_STR);
                strncat(filter_p, ip_addr, strlen(ip_addr));
                filter_p += strlen(ip_addr);
                LOG("ip_filter_str first line: %s", ip_filter_str);
            }           
            
        }    
        freeaddrinfo(addr_res); 
        
        /*   
        if((hptr = gethostbyname(buf)) == NULL){
            LOG(" gethostbyname error for host:%s\n", buf);
            perror("gethostbyname"); 
            continue;
        } 
        printf("official hostname:%s\n",hptr->h_name);
        if((hptr->h_addrtype == AF_INET) || (hptr->h_addrtype == AF_INET6 )){            
            for(pptr = hptr->h_addr_list; pptr != NULL; pptr++){
                inet_ntop(hptr->h_addrtype, pptr, ip_addr, sizeof(ip_addr));                
                if(first_line == 0){
                    first_line = 1;
                    strncat(ip_filter_str, "src host host ", 14);
                    strncat(ip_filter_str, ip_addr, 16);
                }
                else if(first_line == 1){
                    //strncat(ip_filter_str, "or src host host ", 17);
                    strncat(ip_filter_str, " or ", 4);
                    strncat(ip_filter_str, ip_addr, 16);
                }             
                LOG("ip = %s", ip_addr);                
            }
        }
        else printf("unknown address type\n");  
        */                                                
    }
    return R_P_OK;
}

int get_iplist_in_file_2(char* file_name, filter_ip_list_p** new_list_p){
    FILE *fp;
    char* p = NULL;
    char buf[LINE] = {'\0'};
    char static first_line = 0;
    char ip_addr[16] = {'\0'};
    
    struct addrinfo hints;
    struct addrinfo *addr_res, *addr_cur; 
    struct sockaddr_in *addr_p;
    filter_ip_list_p* new_list = NULL; 
    filter_ip_list_p* cur_list_node = NULL;
    filter_ip_list_p* next_list_node = NULL;
     
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    //Allow IPv4 or IPv6 
    hints.ai_socktype = SOCK_DGRAM; // Datagram socket  
    hints.ai_flags = AI_PASSIVE;    // For wildcard IP address 
    hints.ai_protocol = 0;          // Any protocol 
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    if ((fp=fopen(file_name, "r")) == NULL) {
        ERR_EXIT(1, "open file %s error\n", file_name);
    }
    
    while(1) {
        first_line = 1;
        memset(buf, 0, LINE);
        p = fgets(buf, LINE, fp);
        if(!p){
            LOG("close file %s", file_name);
            fclose(fp);
            break;                
        }  
        buf[strlen(buf)-1]=0;        
        LOG("get host name: %s", buf);
        
        if (getaddrinfo(buf, NULL, &hints, &addr_res) == -1) {
            perror("getaddrinfo");            
        }
        if(addr_res == NULL){
            LOG("addr_res is NULL");
            continue;
        }
        for (addr_cur = addr_res; addr_cur != NULL; addr_cur = addr_cur->ai_next) {
            addr_p = (struct sockaddr_in *)addr_cur->ai_addr;
            memset(ip_addr, 0, 16);
            inet_ntop(AF_INET, &addr_p->sin_addr, ip_addr, 16);
            LOG("ip = %s", ip_addr);
            if (memcmp("0.0.0.0", ip_addr, strlen("0.0.0.0")-1)== 0)  {
                LOG("ignore this loop");
                continue;
            }                         
            if(first_line == 1){  
                *new_list_p = (filter_ip_list_p*)malloc(sizeof(filter_ip_list_p));
                new_list = *new_list_p;
                if (new_list == NULL)
                    continue;
                memset(new_list, 0, sizeof(filter_ip_list_p));
                cur_list_node = new_list;
                cur_list_node->head = new_list;
                cur_list_node->next = NULL;                      
                strncpy(cur_list_node->ip_str, ip_addr, strlen(ip_addr));
                first_line = 0;
                LOG("add ip_filter_str line: %s", cur_list_node->ip_str);
                
            }  
            else if(first_line == 0){
                next_list_node = (filter_ip_list_p*)malloc(sizeof(filter_ip_list_p));
                memset(next_list_node, 0, sizeof(filter_ip_list_p)); 
                strncpy(next_list_node->ip_str, ip_addr, strlen(ip_addr));
                next_list_node->head = new_list; 
                next_list_node->next = NULL;               
                cur_list_node->next = next_list_node;  
                cur_list_node = next_list_node;                                                    
                first_line = 0;
                LOG("add ip_filter_str line: %s", cur_list_node->ip_str);
                
            }           
            
        }    
        freeaddrinfo(addr_res);                                            
    }
    for(cur_list_node = new_list; cur_list_node != NULL; cur_list_node = cur_list_node->next){
        LOG("all ip_filter_str line: %s", cur_list_node->ip_str);
    }
    return R_P_OK;
}

char check_ip_list_change(filter_ip_list_p* old_list, filter_ip_list_p* new_list){    
    filter_ip_list_p* cur_new_node = NULL;
    filter_ip_list_p* cur_old_node = NULL;
    if(old_list == NULL){
        return -1;
    }
    for(cur_new_node = new_list->head; cur_new_node != NULL; cur_new_node = cur_new_node->next){
        for(cur_old_node = old_list->head; cur_old_node != NULL; cur_old_node = cur_old_node->next){
            if(strncmp(cur_new_node->ip_str, cur_old_node->ip_str, 16) == 0){
                break;
            }
            if (cur_old_node->next == NULL){
                return -1;
            }
        }
    }
    return 0;
}

char* make_ip_filter_str(filter_ip_list_p* new_list){
    int len = 0;
    filter_ip_list_p* cur_new_node = NULL;
    for(cur_new_node = new_list; cur_new_node != NULL; cur_new_node = cur_new_node->next){
        len ++;
    }
    LOG("list table len is %d", len);   
    //ip str length = 16, " or " str length = 4,"dst port 80 and dst host " str length = 25
    len = 20*len+strlen(FILTER_BASE_STR)+1;
    LOG("list str len is %d", len); 
    char* list_str = malloc(len);
    char* str_start = list_str;
    if (list_str == NULL){
        LOG("malloc for list_str error");
        return NULL;
    }
    memset(list_str, 0, len);
    strncpy(list_str, FILTER_BASE_STR, strlen(FILTER_BASE_STR));
    list_str+=strlen(FILTER_BASE_STR);
    for(cur_new_node = new_list; cur_new_node != NULL; cur_new_node = cur_new_node->next){
        if (cur_new_node == new_list){
            strncpy(list_str, cur_new_node->ip_str, strlen(cur_new_node->ip_str));
            LOG("add first line %s", cur_new_node->ip_str);              
            list_str+=strlen(cur_new_node->ip_str);             
        }
        else{
            strncpy(list_str, " or ", 4);
            list_str+=4;
            strncpy(list_str, cur_new_node->ip_str, strlen(cur_new_node->ip_str));
            LOG("add other line %s", cur_new_node->ip_str);
            list_str+=strlen(cur_new_node->ip_str); 
        }        
    }    
    LOG("filter str = %s ", str_start);
    return str_start;
}
void get_ip_loop(int socket_w_fd, char* check_host_filename){
    //char ip_filter_str[IP_LIST_BUFFER_LEN] = {'\0'};
    //char ip_filter_str_backup[IP_LIST_BUFFER_LEN] = {'\0'};
    char* ip_filter_str = NULL;
    filter_ip_list_p* tmp_node = NULL;
    filter_ip_list_p* tmp_next_node = NULL;
    filter_ip_list_p* new_list = NULL;
    while(1){
        //memset(ip_filter_str, 0, IP_LIST_BUFFER_LEN);
        if (get_iplist_in_file_2(check_host_filename, &new_list) != R_P_OK){
            ERR_EXIT(1, "get host list error\n");        
        }
        /*
        if (get_iplist_in_file(check_host_filename, ip_filter_str) != R_P_OK){
            ERR_EXIT(1, "get host list error\n");        
        }        
        if (strncmp(ip_filter_str_backup, ip_filter_str, IP_LIST_BUFFER_LEN) != 0 ){
            LOG("ip_filter_str_backup: %s", ip_filter_str_backup);
            LOG("ip_filter_str: %s", ip_filter_str);
            strncpy(ip_filter_str_backup, ip_filter_str, IP_LIST_BUFFER_LEN);
            send(socket_w_fd, ip_filter_str_backup, IP_LIST_BUFFER_LEN, 0);
            LOG("send filter str: %s", ip_filter_str_backup);
        } 
        */  
        if (new_list == NULL){
            LOG("new_list is null");
            sleep(120); 
            continue;
        }
        if ((check_ip_list_change(filter_ip_list_backup, new_list) != 0)  ){
            LOG("ip_filter_str_change");
            ip_filter_str = make_ip_filter_str(new_list);  
            if(ip_filter_str == NULL){
                continue;          
            }
            send(socket_w_fd, ip_filter_str, IP_LIST_BUFFER_LEN, 0);
            LOG("send filter str: %s", ip_filter_str);
            free(ip_filter_str);            
            tmp_node = filter_ip_list_backup;
            tmp_next_node = tmp_node;
            filter_ip_list_backup = new_list;
            while(tmp_node != NULL){
                tmp_next_node = tmp_node->next;
                free(tmp_node);
                tmp_node = tmp_next_node;
            }
            tmp_node = NULL;
            tmp_next_node = NULL;
            new_list = NULL;
        }          
        sleep(1800);    
    }   
}