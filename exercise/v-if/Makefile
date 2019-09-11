CC:=gcc
EXEC:= tun.out 
CFLAGS:=-std=c99

all: $(EXEC)

%.out: %.c
	$(CC) $^ -o $@ $(CXXFLAGS)

.PHONY: clean
clean:
	rm -rf $(EXEC)