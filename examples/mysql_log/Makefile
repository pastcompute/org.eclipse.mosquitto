CFLAGS=-Wall -ggdb
LDFLAGS=../../lib/libeecloud.so.1 -lmysqlclient

.PHONY: all clean

all : eecloud_mysql_log

eecloud_mysql_log : mysql_log.o
	${CC} $^ -o $@ ${LDFLAGS}

mysql_log.o : mysql_log.c
	${CC} -c $^ -o $@ ${CFLAGS} -I../../lib

clean : 
	-rm -f *.o eecloud_mysql_log
