objects = main.o send_queue.o cycle_getip.o packet_filter.o make_packet.o
.PHONY: default clean 
default:$(objects)
	gcc -o ptest $(objects) -fPIC -lpthread -lpcap
packet_filter.o:
	gcc -c packet_filter.c	
send_queue.o:
	gcc -c send_queue.c	
cycle_getip.o:
	gcc -c cycle_getip.c
make_packet.o:
	gcc -c make_packet.c	
main.o:
	gcc -c main.c		
clean:
	rm ptest $(objects)

