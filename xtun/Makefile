CC = g++
CFLAGS = -std=c++11
CDEBUG_FLAGS = -g
CSHARED = -shared

SRC_PATH = ./src
OBJ_PATH = ./obj
BIN_PATH = ./bin
DBG_PATH = ./debug

TARGET_SERVER = tunserver
DEBUG_TARGET_SERVER = $(addsuffix _g, $(TARGET_SERVER))

TARGET_CLIENT = tunclient
DEBUG_TARGET_CLIENT = $(addsuffix _g, $(TARGET_CLIENT))

# clean files list
DISTCLEAN_LIST := $(OBJ_PATH)/* \
                  $(DBG_PATH)/*
CLEAN_LIST := $(BIN_PATH)/* \
			  $(DISTCLEAN_LIST)

defaut: all

.PHONY: all
all: $(BIN_PATH)/$(TARGET_SERVER) $(BIN_PATH)/$(TARGET_CLIENT)

# server
$(BIN_PATH)/$(TARGET_SERVER): $(OBJ_PATH)/tunserver.o $(OBJ_PATH)/server.o $(OBJ_PATH)/select_demultiplexer.o \
								$(OBJ_PATH)/reactor.o $(OBJ_PATH)/tnet.o $(OBJ_PATH)/timer_pool.o \
								$(OBJ_PATH)/epoll_demultiplexer.o $(OBJ_PATH)/md5.o $(OBJ_PATH)/inifile.o \
								$(OBJ_PATH)/logger.o
	$(CC) $(CFLAGS) -o $@ $^

# client
$(BIN_PATH)/$(TARGET_CLIENT): $(OBJ_PATH)/tunclient.o $(OBJ_PATH)/client.o $(OBJ_PATH)/select_demultiplexer.o \
								$(OBJ_PATH)/reactor.o $(OBJ_PATH)/tnet.o $(OBJ_PATH)/timer_pool.o \
								$(OBJ_PATH)/epoll_demultiplexer.o $(OBJ_PATH)/md5.o $(OBJ_PATH)/inifile.o \
								$(OBJ_PATH)/logger.o
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c*
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: debug
debug: $(BIN_PATH)/$(DEBUG_TARGET_SERVER) $(BIN_PATH)/$(DEBUG_TARGET_CLIENT)

# server
$(BIN_PATH)/$(DEBUG_TARGET_SERVER): $(DBG_PATH)/tunserver.o $(DBG_PATH)/server.o $(DBG_PATH)/select_demultiplexer.o \
								$(DBG_PATH)/reactor.o $(DBG_PATH)/tnet.o $(DBG_PATH)/timer_pool.o \
								$(DBG_PATH)/epoll_demultiplexer.o $(DBG_PATH)/md5.o $(DBG_PATH)/inifile.o \
								$(DBG_PATH)/logger.o
	$(CC) $(CFLAGS) -o $@ $^

# client
$(BIN_PATH)/$(DEBUG_TARGET_CLIENT): $(DBG_PATH)/tunclient.o $(DBG_PATH)/client.o $(DBG_PATH)/select_demultiplexer.o \
								$(DBG_PATH)/reactor.o $(DBG_PATH)/tnet.o $(DBG_PATH)/timer_pool.o \
								$(DBG_PATH)/epoll_demultiplexer.o $(DBG_PATH)/md5.o $(DBG_PATH)/inifile.o \
								$(DBG_PATH)/logger.o
	$(CC) $(CFLAGS) -o $@ $^

$(DBG_PATH)/%.o: $(SRC_PATH)/%.c*
	$(CC) $(CFLAGS) $(CDEBUG_FLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(CLEAN_LIST)

.PHONY: distclean
distclean:
	@rm -f $(DISTCLEAN_LIST)