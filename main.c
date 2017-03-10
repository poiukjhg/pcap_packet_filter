#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "packet_sys_cfg.h"
#include "cycle_getip.h"
#include "packet_filter.h"

int main(int argc, char *argv[]){
    char check_host_filename[1024] = "/tmp/testfile";
    int pid = 0; 
    int fd[2];
    int result = 0;
    int i = 0;
    for (i=1; i<argc; i++) {
		char *arg=argv[i];  
        if (strcmp(arg,"-c")==0 || strcmp(arg,"--config-file")==0) {
			if (++i<argc) {
                strncpy(check_host_filename, argv[i], strlen(argv[i]));			
			} else {
				fprintf(stderr,"Error: file name expected after %s option.\n",arg);
				exit(1);
			}
		}     
    }
    result = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
    if (result < 0){
        perror("socketpair() ");
        ERR_EXIT(1, "socketpair error\n");       
    }  
    
    if (fd_nonblocking(fd[0]) == -1) {
       ERR_EXIT(1, "socketpair no blocking\n");      
    }
    if (fd_nonblocking(fd[1]) == -1) {
        ERR_EXIT(1, "socketpair no blocking\n");
    } 
       
    pid = fork();
    if(pid <0){
        ERR_EXIT(1, "fork error\n");
    }
    else if(pid == 0 ){
        close(fd[0]);
        LOG("filter process start");
        sleep(1);
        packet_filter(fd[1]);
    }
    else{
        close(fd[1]);
        LOG("get ip process start");
        get_ip_loop(fd[0], check_host_filename);
    }              
}
