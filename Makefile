############################################################
# Project:
############################################################

PROJECT	= dtls-handler
TARGET	= dtls-handler


############################################################
# Compilation flags:
############################################################

INCDIR		= -I./include
LIBDIR		=
LIBRARIES	= $(LIBDIR) -lssl -lcrypto -lpthread
INCLUDE		= $(INCDIR)
CFLAGS 		=	-Werror			\
			-W			\
			-Wall			\
			-Wextra			\
			-Wno-multichar		\
			-Wno-strict-aliasing		\
			-Wtrigraphs		\
			-Wswitch		\
			-Wunused		\
			-Wimplicit		\
			-Wcast-qual		\
			-Wcast-align		\
			-Wwrite-strings		\
			-Wuninitialized		\
			-Winit-self		\
			-Wnested-externs	\
			-Waggregate-return	\
			-Wshadow		\
			-fno-common		\
			-std=gnu99

# For debug and valgrind
ifdef DEBUG
	CFLAGS += -g -ggdb3
else
	CFLAGS += -O2
endif

ifdef VALGRIND
	CFLAGS += -g -DGLIBC_FORCE_NEW -ggdb3
endif

CFLAGS+= $(INCLUDE)


############################################################
# Files and directories
############################################################

SRC = src
BIN = bin
OBJ = obj
INC = ./include
OBJ_DIR = $(OBJ)
BIN_DIR = $(BIN)
SRC_FILES = $(wildcard $(SRC)/*.c)
HDR_FILES = $(wildcard $(INC)/*.h)
OBJ_FILES = $(subst $(SRC),$(OBJ_DIR),$(SRC_FILES:.c=.o))


############################################################
# Build:
############################################################

# make all
all: $(BIN_DIR)/$(TARGET)

# making all the *.o
$(OBJ_DIR)/%.o: $(SRC)/%.c $(HDR_FILES)
	$(CC) $(CFLAGS) -o $@ -c $<

# make project
$(BIN_DIR)/$(TARGET): $(OBJ_FILES) 
	$(CC) $(CFLAGS) -o "$(BIN_DIR)/$(TARGET)" $(OBJ_FILES) $(LIBRARIES)


############################################################
# Maintenance:
############################################################

# clean
clean:
	rm -f $(OBJ_FILES)

distclean: clean
	rm -f $(BIN_DIR)/$(TARGET)
