CFLAGS  += -g -Wall -Werror
LDFLAGS = -lbfd

SOURCES = create_hotpatch.c
OBJS = $(patsubst %.c,%.o,$(SOURCES))
TARGETS = $(patsubst %.c,%,$(SOURCES))

.PHONY: clean all

all: $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGETS): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	$(RM) $(TARGETS) $(OBJS)
