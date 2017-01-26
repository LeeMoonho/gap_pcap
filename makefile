result_file : pcap_source.o
	gcc -o result_file pcap_source.o -lpcap -I/usr/include/pcap

pcap_source : pcap_source.c
	gcc -c -o pcap_source.o pcap_source.c -lpcap -I/usr/include/pcap

clean :
	rm *.o result_file
