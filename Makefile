EXEC:=
CC:=gcc
OBJS:= virt.o 
TEST:= test_tun.out test_tap.out

all: $(EXEC) $(OBJS)
test: $(TEST)

%.o: utils/%.c 
	$(CC) -c $^

%.out: test/%.c virt.o
	$(CC) -o $@ $^

.PHONY: clean
clean:
	rm -rf $(EXEC) $(OBJS)