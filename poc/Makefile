# TAGE-SC Branch Predictor Aliasing PoC - Build Instructions

CC      ?= riscv64-linux-gnu-gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11 -march=rv64imac -mabi=lp64
TARGET  := tage_sc_poc

# Allow native x86-64 build for simulation-only mode (no hardware timing)
ifeq ($(shell uname -m),x86_64)
    CC     = gcc
    CFLAGS = -O2 -Wall -Wextra -std=c11
endif

.PHONY: all clean run

all: $(TARGET)

$(TARGET): tage_sc_poc.c tage_model.h
	$(CC) $(CFLAGS) -o $@ tage_sc_poc.c

# Run on the local machine (simulation mode; no RISC-V hardware required)
run: $(TARGET)
	./$(TARGET)

# Cross-compile for a RISC-V Linux target, then copy and execute via SSH
# Usage: make deploy TARGET_HOST=user@riscv-board
deploy: $(TARGET)
	scp $(TARGET) $(TARGET_HOST):/tmp/
	ssh $(TARGET_HOST) /tmp/$(TARGET)

clean:
	rm -f $(TARGET)
