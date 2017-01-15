#OBJECTSCLIENT = client.o common.o md5c.o
OBJECTSSERVER = udp_epoll_server.o
OBJECTSCLIENTEPOLL = client.o md5c.o sockd_rbtree.o  client_process.o
all: client udp-server

client : ${OBJECTSCLIENTEPOLL}
	cc -o client ${OBJECTSCLIENTEPOLL}

client.o : client.c client.h md5c.h sockd_rbtree.h
	cc -c -g client.c 

sockd_rbtree.o:sockd_rbtree.c sockd_rbtree.h
	cc -c -g sockd_rbtree.c
	
client_process.o:client_process.c client.h client_process.h
	cc -c -g client_process.c

md5c.o:md5c.c md5c.h
	cc -c -g md5c.c

udp-server : ${OBJECTSSERVER}
	cc -o udp-server ${OBJECTSSERVER}

udp_epoll_server.o : udp_epoll_server.c
	cc -c -g udp_epoll_server.c 

.PHONY:clean

clean:
	rm -f *.o client udp-server
