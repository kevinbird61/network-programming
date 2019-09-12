EXEC:=
CC:=gcc
OBJS:= virt.o 
TEST:= test_tun.out

all: $(EXEC) $(OBJS)
test: $(TEST)

%.o: utils/%.c 
	$(CC) -c $^

test_tun.out: test/test_tun.c virt.o
	$(CC) -o $@ $^

.PHONY: clean
clean:
	rm -rf $(EXEC) $(OBJS)