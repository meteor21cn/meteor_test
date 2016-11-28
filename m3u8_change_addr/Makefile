hls:  hls_http.o
	gcc -o hls hls_http.o  && ./hls > test.txt

hls_http.o: hls_http.c
	gcc -c -g hls_http.c -std=c99

clean:
	rm hls hls_http.o