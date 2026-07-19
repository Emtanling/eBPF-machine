# SPDX-License-Identifier: MIT
CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
UNAME_M := $(shell uname -m)
ARCH := $(shell echo $(UNAME_M) | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/ppc64le/powerpc/' -e 's/riscv64/riscv/')
BUILD := build
VMLINUX := $(BUILD)/vmlinux.h
VMLINUX_SHA := $(BUILD)/vmlinux.h.btf.sha256
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || echo '-lbpf -lelf -lz')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror \
	-I$(BUILD) -Iinclude -Itracer -Iwitness $(LIBBPF_CFLAGS)
USER_CFLAGS := -g -O2 -Wall -Wextra -I$(BUILD) -Iinclude $(LIBBPF_CFLAGS)
V2_TARGETS := $(BUILD)/rac-v2-collect-fentry $(BUILD)/rac-v2-witness

.PHONY: all clean preflight v2 FORCE
all: $(BUILD)/rac-collect-fexit $(BUILD)/rac-collect-kprobe $(BUILD)/rac-witness \
	$(V2_TARGETS)

v2: $(V2_TARGETS)

$(BUILD):
	mkdir -p $@

$(VMLINUX): FORCE | $(BUILD)
	@test -r /sys/kernel/btf/vmlinux || (echo 'missing /sys/kernel/btf/vmlinux' >&2; exit 1)
	@current="$$(sha256sum /sys/kernel/btf/vmlinux | awk '{print $$1}')"; \
	previous="$$(cat $(VMLINUX_SHA) 2>/dev/null || true)"; \
	if [ ! -f $@ ] || [ "$$current" != "$$previous" ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
		printf '%s\n' "$$current" > $(VMLINUX_SHA); \
	fi

$(BUILD)/rac_tracer_fexit.bpf.o: tracer/rac_tracer_fexit.bpf.c tracer/rac_tracer_common.bpf.h tracer/verifier_state_v2.h include/rac_events.h $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/rac_tracer_kprobe.bpf.o: tracer/rac_tracer_kprobe.bpf.c tracer/rac_tracer_common.bpf.h tracer/verifier_state_v2.h include/rac_events.h $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/rac_witness.bpf.o: witness/rac_witness.bpf.c $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/rac_v2_tracer_fentry.bpf.o: tracer/rac_v2_tracer_fentry.bpf.c tracer/rac_v2_tracer_common.bpf.h tracer/verifier_state_v2.h include/rac_events.h include/rac_v2_events.h $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/rac_v2_witness.bpf.o: witness/rac_v2_witness.bpf.c witness/rac_v2_witness.h $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/rac_tracer_fexit.skel.h: $(BUILD)/rac_tracer_fexit.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/rac_tracer_kprobe.skel.h: $(BUILD)/rac_tracer_kprobe.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/rac_witness.skel.h: $(BUILD)/rac_witness.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/rac_v2_tracer_fentry.skel.h: $(BUILD)/rac_v2_tracer_fentry.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/rac_v2_witness.skel.h: $(BUILD)/rac_v2_witness.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/rac-collect-fexit: tracer/rac_collect_fexit.c tracer/state_collector.c $(BUILD)/rac_tracer_fexit.skel.h include/rac_events.h
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

$(BUILD)/rac-collect-kprobe: tracer/rac_collect_kprobe.c tracer/state_collector.c $(BUILD)/rac_tracer_kprobe.skel.h include/rac_events.h
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

$(BUILD)/rac-witness: witness/rac_witness.c $(BUILD)/rac_witness.skel.h
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

$(BUILD)/rac-v2-collect-fentry: tracer/rac_v2_collect_fentry.c tracer/state_collector.c $(BUILD)/rac_v2_tracer_fentry.skel.h include/rac_events.h include/rac_v2_events.h
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

$(BUILD)/rac-v2-witness: witness/rac_v2_witness.c witness/rac_v2_witness.h $(BUILD)/rac_v2_witness.skel.h
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

preflight:
	./scripts/preflight.sh

clean:
	rm -rf $(BUILD)
