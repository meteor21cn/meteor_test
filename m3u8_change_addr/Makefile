hls:  hls_http.o http.o
	gcc -o hls hls_http.o http.o 

http.o: http.c
	gcc -c -g  http.c

hls_http.o: hls_http.c lib/md5c.c
	gcc -c -g hls_http.c lib/md5c.c -std=c99

clean:
	-rm hls *.o lib/md5c.o
