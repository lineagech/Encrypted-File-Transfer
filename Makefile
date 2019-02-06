#
# File          : Makefile
#                 

# Environment Setup
LIBDIRS=-L. -L/usr/lib64/
INCLUDES=-I. -I/usr/include/
CC=gcc 
# remove -DDEBUG to remove debugging output
CFLAGS=-c $(INCLUDES) -g -Wall -DDEBUG
LINK=gcc -g
LDFLAGS=$(LIBDIRS)
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=client \
	server
CRLIB=crlib
CRLIBOBJS=transfer.o \
		 siis-network.o \
		 siis-ssl.o \
		 siis-util.o 
LIBS=-lcrypto -lm 

#
# Project Protections

p1 : $(TARGETS)

client : main.o lib$(CRLIB).a
	$(LINK) $(LDFLAGS) main.o $(LIBS) -l$(CRLIB) -o $@

server : main.o lib$(CRLIB).a
	$(CC) $(CFLAGS) main.c -DSERVER -o server.o 
	$(LINK) $(LDFLAGS) server.o $(LIBS) -l$(CRLIB) -o $@

lib$(CRLIB).a : $(CRLIBOBJS)
	$(AR) $@ $(CRLIBOBJS)
	$(RANLIB) $@

clean:
	rm -f *.o *~ $(TARGETS) lib$(CRLIB).a

BASENAME=trans
tar: 
	tar cvfz $(BASENAME).tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/main.c \
	    $(BASENAME)/transfer.c \
	    $(BASENAME)/transfer.h \
	    $(BASENAME)/siis-network.c \
	    $(BASENAME)/siis-network.h \
	    $(BASENAME)/siis-ssl.c \
	    $(BASENAME)/siis-ssl.h \
	    $(BASENAME)/siis-util.c \
	    $(BASENAME)/siis-util.h 

