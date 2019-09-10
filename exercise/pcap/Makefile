CC:=g++
EXEC:= readcap.out 
CXXFLAGS:=-std=c++11

all: $(EXEC)

%.out: %.cc
	$(CC) $^ -o $@ -lm -lpcap $(CXXFLAGS)

.PHONY: clean
clean:
	rm -rf $(EXEC)