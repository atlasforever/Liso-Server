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
lisod.o: lisod.c log.h common.h parse.h request.h
log.o: log.c log.h common.h
parse.o: parse.c parse.h common.h log.h
request.o: request.c http_common.h parse.h common.h request.h
y.tab.o: y.tab.c parse.h


lisod: $(objects)
	$(CC) $(objects) -o lisod $(CFLAGS)

clean:
	@rm lisod *.o lex.yy.c y.tab.c y.tab.h y.tab.h.gch
