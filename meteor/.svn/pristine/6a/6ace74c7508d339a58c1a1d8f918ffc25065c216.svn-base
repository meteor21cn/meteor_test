LDFLAGS = -lhiredis -lpthread -lm
LIB = ../lib/
OBJECTS = meteor.o sockd.o sockd_udp.o sockd_tcp.o sockd_auth.o order.o rbtree.o \
		redis.o md5c.o log.o meteor_process.o  meteor_conf.o

all:meteor
meteor : ${OBJECTS}
	cc -o  meteor -g ${OBJECTS} ${LDFLAGS} 

meteor.o:meteor.c meteor.h
	cc -c  -g meteor.c

sockd.o:sockd.c sockd.h
	cc -c  -g sockd.c

sockd_udp.o: sockd_udp.c sockd_udp.h
	cc -c -g sockd_udp.c

sockd_tcp.o: sockd_tcp.c sockd_tcp.h
	cc -c -g sockd_tcp.c

sockd_auth.o: sockd_auth.c sockd_auth.h
	cc -c -g sockd_auth.c

order.o: order.c order.h
	cc -c -g order.c

rbtree.o:sockd_rbtree.c sockd_rbtree.h
	cc -c  -g sockd_rbtree.c -o rbtree.o

redis.o:sockd_redis.c sockd_redis.h
	cc -c  -g sockd_redis.c -o redis.o
	
md5c.o:${LIB}md5c.c ${LIB}md5c.h
	cc -c  -g ${LIB}md5c.c

log.o: log.c log.h
	cc -c -g log.c

meteor_process.o: meteor_process.c meteor_process.h
	cc -c -g meteor_process.c

meteor_conf.o:meteor_conf.c meteor_conf.h sockd.h meteor.h
	cc -c -g   meteor_conf.c

.PHONY:clean

clean:
	rm -f *.o meteor
