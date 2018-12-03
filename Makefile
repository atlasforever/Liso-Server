################################################################################
# Makefile                                                                     #
#                                                                              #
# Description: This file contains the make rules for Recitation 1.             #
#                                                                              #
# Authors: Athula Balachandran <abalacha@cs.cmu.edu>,                          #
#          Wolf Richter <wolf@cs.cmu.edu>                                      #
#                                                                              #
################################################################################
CC= gcc
CFLAGS= -Wall -Werror
LDLIBS = -lssl -lcrypto
objects= lisod.o log.o parse.o y.tab.o lex.yy.o request.o

.PHONY: default clean

default: lisod

lex.yy.c: lexer.l
	flex $^

y.tab.c: parser.y
	yacc -d $^

# Automatically generated
lex.yy.o: lex.yy.c y.tab.h
	$(CC) $^ -c
lisod.o: lisod.c lisod.h http_common.h log.h parse.h request.h
log.o: log.c log.h lisod.h
parse.o: parse.c parse.h request.h lisod.h log.h
request.o: request.c http_common.h log.h parse.h request.h lisod.h
y.tab.o: y.tab.c parse.h
	$(CC) $^ -c

lisod: $(objects)
	$(CC) $(objects) -o lisod $(CFLAGS) $(LDLIBS)

clean:
	@rm lisod *.o lex.yy.c y.tab.c y.tab.h *.h.gch
