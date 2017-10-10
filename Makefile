all:send_arp

send_arp: func.o main.o
	gcc -o send_arp func.o main.o -lpcap

func.o: func.c my_pcap.h
	gcc -c -o func.o func.c -lpcap

main.o: main.c my_pcap.h
	gcc -c -o main.o main.c

clean:
	rm *.o send_arp
