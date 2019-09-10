CC:=gcc 
OBJS:= server.out client.out

all: $(OBJS)

%.out: %.c 
	$(CC) $^ -o $@

.PHONY: clean
clean:
	rm -rf $(OBJS)