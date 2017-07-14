all: pcap_test
pcap_test: packet_parse.o main.o
	gcc -o pcap_test packet_parse.o main.o -lpcap

packet_parse.o: packet_parse.c packet_parse.h
	gcc -c -o packet_parse.o packet_parse.c -lpcap

main.o: main.c packet_parse.h
	gcc -c -o main.o main.c

clean: 
	rm main.o packet_parse.o
