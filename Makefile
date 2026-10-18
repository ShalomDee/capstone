CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=gnu11 -Icommon
LDLIBS  = -loqs -lcrypto -lpthread
BUILD   = build

# Shared code used by every program
COMMON_SRC = common/protocol.c common/framing.c common/securenet.c common/identity.c common/bench.c
COMMON_OBJ = $(COMMON_SRC:common/%.c=$(BUILD)/common/%.o)
HEADERS    = $(wildcard common/*.h)

# Sensor reading format and wire byte counts, shared by the sensor and the tests
SENSOR_LIB = sensor/reading.c sensor/wire_cost.c
SENSOR_HDR = sensor/reading.h sensor/wire_cost.h

PROGRAMS = $(BUILD)/server $(BUILD)/client $(BUILD)/sensor $(BUILD)/time_sign $(BUILD)/time_pqc $(BUILD)/pqc_demo

.PHONY: all demo test bench sensor-sizes clean

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

# "make sensor-sizes" uploads 100 simulated readings in files of 1, 10 and 100
sensor-sizes: $(BUILD)/sensor
	./$(BUILD)/sensor field-a-01 100 1 $(BUILD)/sensor-data
	./$(BUILD)/sensor field-a-01 100 10 $(BUILD)/sensor-data
	./$(BUILD)/sensor field-a-01 100 100 $(BUILD)/sensor-data

$(BUILD)/common/%.o: common/%.c $(HEADERS) | $(BUILD)/common
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/server: server/main.c server/handlers.c server/handlers.h $(COMMON_OBJ)
	$(CC) $(CFLAGS) -Iserver server/main.c server/handlers.c $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/client: client/main.c client/commands.c client/commands.h $(COMMON_OBJ)
	$(CC) $(CFLAGS) -Iclient client/main.c client/commands.c $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/sensor: sensor/sensor.c $(SENSOR_LIB) $(SENSOR_HDR) $(COMMON_OBJ)
	$(CC) $(CFLAGS) -Isensor sensor/sensor.c $(SENSOR_LIB) $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/time_sign: bench/time_sign.c $(COMMON_OBJ)
	$(CC) $(CFLAGS) $< $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/time_pqc: bench/time_pqc.c | $(BUILD)
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(BUILD)/test_main: tests/test_main.c $(SENSOR_LIB) $(SENSOR_HDR) $(COMMON_OBJ)
	$(CC) $(CFLAGS) -Isensor tests/test_main.c $(SENSOR_LIB) $(COMMON_OBJ) $(LDLIBS) -o $@

$(BUILD)/pqc_demo: demo/pqc_demo.c | $(BUILD)
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(BUILD) $(BUILD)/common:
	mkdir -p $@

clean:
	rm -rf $(BUILD)
