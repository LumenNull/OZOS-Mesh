# =============================================================================
#   O.Z.O.S // SOVEREIGN MESH P2P ROUTER (Makefile)
#   Cross-Platform POSIX / Linux / macOS / MinGW Build & Verification System
#   Compliance: C99 / Zero-Heap (malloc=0) / OZOS-80 Wire Invariant
# =============================================================================

CC          ?= cc
CFLAGS      ?= -std=c99 -O3 -Wall -Wextra -Werror -pedantic -Wno-sign-compare -Iinclude
NACL_CFLAGS ?= -std=c99 -O3 -Iinclude

ifeq ($(OS),Windows_NT)
    EXE_EXT := .exe
    LDLIBS  := -ladvapi32 -lwinmm -lm
    PYTHON  ?= python
else
    EXE_EXT :=
    LDLIBS  := -lm
    PYTHON  ?= python3
endif

TARGET_BIN := ozos-mesh$(EXE_EXT)
TEST_BIN   := test_security_hardening$(EXE_EXT)

.PHONY: all test mutation clean

all: $(TARGET_BIN) $(TEST_BIN)

tweetnacl.o: src/tweetnacl.c include/tweetnacl.h
	$(CC) $(NACL_CFLAGS) -c src/tweetnacl.c -o tweetnacl.o

$(TARGET_BIN): src/main.c tweetnacl.o include/ozos_mesh.h include/ozos_mesh_phy.h include/tweetnacl.h
	$(CC) $(CFLAGS) src/main.c tweetnacl.o -o $(TARGET_BIN) $(LDLIBS)

$(TEST_BIN): tests/test_security_hardening.c tweetnacl.o include/ozos_mesh.h include/ozos_mesh_phy.h include/tweetnacl.h
	$(CC) $(CFLAGS) tests/test_security_hardening.c tweetnacl.o -o $(TEST_BIN) $(LDLIBS)

test: all
	./$(TEST_BIN)
	$(PYTHON) tests/test_mesh_network.py
	$(PYTHON) tests/sim_mesh_topology.py
	$(PYTHON) tests/live_mesh_demo.py

mutation: all
	$(PYTHON) tests/mutation_test.py

clean:
	rm -f $(TARGET_BIN) $(TEST_BIN) *.o *.obj *.pdb
