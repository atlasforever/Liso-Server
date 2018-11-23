################################################################################
# Makefile                                                                     #
#                                                                              #
# Description: This file contains the make rules for Recitation 1.             #
#                                                                              #
# Authors: Athula Balachandran <abalacha@cs.cmu.edu>,                          #
#          Wolf Richter <wolf@cs.cmu.edu>                                      #
#                                                                              #
################################################################################

default: lisod echo_client log.o


echo_client:
	@gcc echo_client.c -o echo_client -Wall -Werror

log.o:
	@gcc log.c -c -Wall -Werror

lisod: log.o lisod.c
	@gcc lisod.c log.o -o lisod -Wall -Werror

clean:
	@rm *.o y.tab.* lisod echo_client
