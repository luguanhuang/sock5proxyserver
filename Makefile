#
# Makefile - makefile to build the base system
#

# Locations

# Make environment
CC=g++
# CFLAGS=-c -Wall -Wextra -fsanitize=address -fno-omit-frame-pointer -O1
CFLAGS=-c -Wall -Wextra -fno-omit-frame-pointer -O1
#CFLAGS += -D_XOPEN_SOURCE=500
CFLAGS += -g 
LIBS= -lpthread
# Suffix rules
.SUFFIXES: .cpp .o

.cpp.o:
	$(CC) $(CFLAGS)  -o $@ $<  
	
# Files
OBJECT_FILES= proxyserver.o sock5proxy.o log_lib_cplus.o cdatetime_lib.o server.o threadpool.o 

# Productions
all : proxyserver

proxyserver : $(OBJECT_FILES)
	# $(CC) -fsanitize=address  $(OBJECT_FILES) -o $@ $(LIBS)
	$(CC)  $(OBJECT_FILES) -o $@ $(LIBS)

clean : 
	rm -f proxyserver $(OBJECT_FILES)
	
