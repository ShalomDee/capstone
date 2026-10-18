CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=gnu11 -Icommon
LDLIBS  = -loqs -lcrypto -lpthread
BUILD   = build

# Shared code used by every program
COMMON_SRC = common/protocol.c common/framing.c common/securenet.c common/identity.c common/bench.c
COMMON_OBJ = $(COMMON_SRC:common/%.c=$(BUILD)/common/%.o)
HEADERS    = $(wildcard common/*.h)

PROGRAMS = $(BUILD)/server $(BUILD)/client $(BUILD)/sensor $(BUILD)/time_sign $(BUILD)/time_pqc $(BUILD)/pqc_demo

.PHONY: all demo test bench clean

# "make" builds every program into build/
all: $(PROGRAMS)

# "make demo" builds and runs the first proof-it-works program
demo: $(BUILD)/pqc_demo
	./$(BUILD)/pqc_demo

# "make test" builds everything, then runs the tests
test: all $(BUILD)/test_main
	./$(BUILD)/test_main

# "make bench" builds and runs the liboqs timing program (1000 runs each)
bench: $(BUILD)/time_pqc
	./$(BUILD)/time_pqc 1000

$(BUILD)/common/%.o: common/%.c $(HEADERS) | $(BUILD)/common
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/server: server/main.c server/handlers.c server/handlers.h $(COMMON_OBJ)
	$(CC) $(CFLAGS) -Iserver server/main.c server/handlers.c $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/client: client/main.c client/commands.c client/commands.h $(COMMON_OBJ)
	$(CC) $(CFLAGS) -Iclient client/main.c client/commands.c $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/sensor: sensor/sensor.c $(COMMON_OBJ)
	$(CC) $(CFLAGS) $< $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/time_sign: bench/time_sign.c $(COMMON_OBJ)
	$(CC) $(CFLAGS) $< $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/time_pqc: bench/time_pqc.c | $(BUILD)
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(BUILD)/test_main: tests/test_main.c $(COMMON_OBJ)
	$(CC) $(CFLAGS) $< $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/pqc_demo: demo/pqc_demo.c | $(BUILD)
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(BUILD) $(BUILD)/common:
	mkdir -p $@

clean:
	rm -rf $(BUILD)
