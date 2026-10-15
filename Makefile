CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=gnu11
LDLIBS  = -loqs -lcrypto -lpthread
BUILD   = build

.PHONY: all demo clean

all: demo

# "make demo" builds and runs the first proof-it-works program
demo: $(BUILD)/pqc_demo
	./$(BUILD)/pqc_demo

$(BUILD)/pqc_demo: demo/pqc_demo.c | $(BUILD)
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
