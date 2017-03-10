#ifndef PACKET_SYS_CFG
#define  PACKET_SYS_CFG
    #define R_P_OK 0
    #define R_P_ERR -1
    #define LINE 1024
    //#define DEBUG
    #define ERR_EXIT(exit_no, format, ...) do{ \
                                                fprintf(stderr, format, ##__VA_ARGS__); \
                                                exit(exit_no);   \
                                              }while(0)  
                                               
    #define fd_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
    #ifdef DEBUG
        #define LOG(format, ...) printf(">> "format"\n", ##__VA_ARGS__)
    #else
        #define LOG(format, ...)
    #endif 
    
    #define IP_LIST_NOT_CHANGED 0
    #define IP_LIST_CHANGED 1
    #define IP_LIST_BUFFER_LEN 16*1024
       
     
#endif