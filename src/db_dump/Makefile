include ../../config.mk

CFLAGS_FINAL=${CFLAGS} -I.. -I../../lib -I../..

.PHONY: all clean reallyclean

all : eecloud_db_dump

eecloud_db_dump : db_dump.o
	${CROSS_COMPILE}${CC} $^ -o $@ ${LDFLAGS} ${LIBS}

db_dump.o : db_dump.c ../persist.h
	${CROSS_COMPILE}${CC} $(CFLAGS_FINAL) -c $< -o $@

clean : 
	-rm -f *.o eecloud_db_dump
