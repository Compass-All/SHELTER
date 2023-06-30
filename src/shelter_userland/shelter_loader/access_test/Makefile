CURRENT_DIR := $(CURDIR)
PROJ_DIR := $(abspath $(CURRENT_DIR)/../../../..)
CPP = $(PROJ_DIR)/third-parties/dev_workspace/tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc
CPPFLAGS = -g -static


SRC = access_test.c
OBJ = $(SRC:.c=.o)
EXEC = access_test

all: $(EXEC)

$(EXEC): $(SRC)
	$(CPP) $(CPPFLAGS) -o $(EXEC) $(SRC) $(LIBS)

clean:
	rm -rf *.o $(EXEC)