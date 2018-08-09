TARGET:=main
CROSS:=
CC:=$(CROSS)gcc
ECHO:=@

SSRC+=$(shell find . -name '*.s')
CSRC+=$(shell find . -name '*.c')
CPPSRC+=$(shell find . -name '*.cpp')
OBJS+=$(SSRC:%.s=%.o)
OBJS+=$(CSRC:%.c=%.o)
OBJS+=$(CPPSRC:%.cpp=%.o)

ALLPATHS:=$(shell ls -R | grep :)
CFLAGS+=$(ALLPATHS:%:=-I%)
CFLAGS+=-I.
CFLAGS+=-DDEBUG=1
CFLAGS+=-c -O0 -ggdb

CSFLAGS+=$(CFLAGS)
CCFLAGS+=$(CFLAGS) -std=gnu11
CCPPFLAGS+=$(CFLAGS) -std=gnu++11

LDFLAGS+=$(ALLPATHS:%:=-L%)
LDFLAGS+=-O0 -ggdb
LDFLAGS+=-L.
LDFLAGS+=-lpcap -lpthread -lstdc++ -lm -lc

.PHONY:all clean
all:$(TARGET).elf
	@echo -e '[33m[GO] [32m$<[0m'
	$(ECHO)./$<
$(TARGET).elf:$(OBJS)
	@echo -e '[33m[LD] [32m$@[0m'
	$(ECHO)$(CC) -o $@ $^ $(LDFLAGS)
%.o:%.s
	@echo -e '[33m[CC] [32m$@[0m'
	$(ECHO)$(CC) -o $@ $^ $(CSFLAGS)
%.o:%.c
	@echo -e '[33m[CC] [32m$@[0m'
	$(ECHO)$(CC) -o $@ $^ $(CCFLAGS)
%.o:%.cpp
	@echo -e '[33m[CC] [32m$@[0m'
	$(ECHO)$(CC) -o $@ $^ $(CCPPFLAGS)
clean:
	@echo -e '[33m[RM] [32m$(TARGET).elf $(OBJS)[0m'
	$(ECHO)rm -rf $(TARGET).elf $(OBJS)
