result_file : pcap_source.c
	gcc -o result_file pcap_source.c -lpcap -I/usr/include/pcap
	
clean :
	rm - rf result_file
