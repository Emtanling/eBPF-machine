CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= cc
PYTHON   ?= python3

SRC      := src
BUILD    := build
RESULTS  := results
TESTS    := tests
SCRIPTS  := scripts
CIRCUITS := circuits
REPORT_RUN := results/interpreter/interpreter-final-20260711-02
INTERPRETER_RUN ?= $(REPORT_RUN)
AUX_R_RUN := results/linux_r/linux-r-v1
STOCK_R_ROOT := residuality-auditor

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),aarch64)
BPF_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
BPF_ARCH := arm64
else ifeq ($(UNAME_M),x86_64)
BPF_ARCH := x86
else
BPF_ARCH := $(UNAME_M)
endif

GATE_CAP ?= 2
EXTRA_BPF_CFLAGS ?=

CFLAGS      ?= -O2 -g -Wall -Wextra -I.
BPF_CFLAGS  ?= -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)

.PHONY: all test data clean env verify circuits interpreter-data \
	verify-interpreter verify-aux-r verify-stock-r

all: $(BUILD)/wm_user $(BUILD)/wm_vm_user

test: $(SRC)/vmlinux.h $(BUILD)/test_logic_model
	$(BUILD)/test_logic_model
	$(PYTHON) $(TESTS)/test_audit_results.py
	$(PYTHON) $(TESTS)/test_circuit_tool.py
	$(PYTHON) $(TESTS)/test_audit_interpreter.py
	$(PYTHON) $(TESTS)/test_interpreter_provenance.py
	$(PYTHON) $(TESTS)/test_status_mask_source.py

CIRCUIT_SPECS := $(wildcard $(CIRCUITS)/*.json)
CIRCUIT_DESCRIPTORS := $(CIRCUIT_SPECS:.json=.wmc)

circuits: $(CIRCUIT_DESCRIPTORS)

$(CIRCUITS)/%.wmc: $(CIRCUITS)/%.json $(SCRIPTS)/circuit_tool.py
	$(PYTHON) $(SCRIPTS)/circuit_tool.py compile $< $@

data: all
	$(SCRIPTS)/run_kernel_suite.sh

interpreter-data:
	bash $(SCRIPTS)/run_interpreter_suite.sh

verify-interpreter:
	@test -d "$(INTERPRETER_RUN)" || \
		{ echo "missing interpreter run: $(INTERPRETER_RUN)" >&2; exit 2; }
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(INTERPRETER_RUN)/source/scripts/audit_interpreter.py $(INTERPRETER_RUN)
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(INTERPRETER_RUN)/source/scripts/write_interpreter_provenance.py verify $(INTERPRETER_RUN)

env:
	mkdir -p $(RESULTS)
	$(PYTHON) $(SCRIPTS)/record_env.py > $(RESULTS)/env.json

$(SRC)/vmlinux.h:
	mkdir -p $(SRC)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/wm.bpf.o: $(SRC)/wm.bpf.c $(SRC)/wm_common.h $(SRC)/vmlinux.h
	mkdir -p $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -DGATE_CAP=$(GATE_CAP) $(EXTRA_BPF_CFLAGS) \
		-c $(SRC)/wm.bpf.c -o $@

$(BUILD)/wm_user: $(SRC)/wm_user.c $(SRC)/wm_common.h $(BUILD)/wm.bpf.o
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< \
		$(LIBBPF_LIBS) -lelf -lz -o $@

$(BUILD)/wm_vm_user: $(SRC)/wm_vm_user.c $(SRC)/wm_common.h $(BUILD)/wm.bpf.o
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< \
		$(LIBBPF_LIBS) -lelf -lz -o $@

$(BUILD)/test_logic_model: $(TESTS)/test_logic_model.c $(SRC)/wm_common.h
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $< -o $@

verify-aux-r:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(AUX_R_RUN)/linux_r_audit.py \
		$(AUX_R_RUN) --require-kernel

verify-stock-r:
	cd $(STOCK_R_ROOT) && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. \
		$(PYTHON) -m tools.proof.check_frozen_bundle stock-linux-r-proof

verify: verify-interpreter verify-aux-r verify-stock-r

clean:
	rm -rf $(BUILD) $(SRC)/vmlinux.h
