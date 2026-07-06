# eBPF Weird Machine PoC

This artifact implements the capacity-saturation NAND PoC described in the
paper draft, plus a second interval-analyzer witness. It is intended for an
isolated Linux VM with root access and BTF enabled.

## What this proves

Full statement in `ARTIFACT.md` (Claims and Scope + Appendix A.9/A.10).
In short:

- **Proven.** The hash-map capacity-saturation gate realizes NAND
  (exhaustive 400/400; by disassembly the output is a map-insert return
  code, not ALU on the inputs). From it: an exhaustive full adder (8/8) and
  8-bit adder (65536/65536); NAND is universal, so any Boolean circuit is
  realizable. Every variant is verifier-accepted (`loadall_exit=0`).
- **The gap, formally.** The verifier holds the insert's return at `⊤`
  (`scalar()`) and forks at the output branch — the occupancy bit carrying
  the gate output is quotiented to `⊤`, a machine-checkable property of its
  abstract semantics (`ARTIFACT.md` A.9).
- **Opacity theorem.** An *exploitable gap* (observable + input-controllable
  + resettable + composable `⊤`-channel) with a complete gate computes every
  Boolean `f` while the abstraction certifies nothing about `f`; the PoC
  discharges every clause (A.10). So eBPF admits *opaque programmable
  computation* of arbitrary Boolean circuits.

**Not** a Turing-completeness or universal "gap ⇒ weird machine" claim, and
not a verifier bypass, privilege escalation, or memory-corruption PoC.

## Requirements

- Isolated Linux VM with root (CAP_BPF/CAP_SYS_ADMIN) and BTF at
  `/sys/kernel/btf/vmlinux`.
- Kernel >= 5.17 for `SEC("syscall")` programs and `bpf_loop()`.
- `clang`, `bpftool`, `libbpf`, and `pkg-config` on the build host.
- Captured feature detection lands in `results/feature_probe.txt`.

## Build

```sh
make test
make
```

## Run

```sh
sudo ./build/wm_user nand 100
sudo ./build/wm_user fa
sudo ./build/wm_user adder 1000
sudo ./build/wm_user adder-exhaustive 8
```

## Full Dataset

```sh
./scripts/run_kernel_suite.sh
```

The suite records JSONL outputs under `results/` for the normal NAND/full-adder
/32-bit-adder runs and for three ablations:

- `GATE_CAP=64`: capacity saturation disappears, NAND becomes all-1.
- `WM_FORCE_SENTINEL_B`: the second input reuses sentinel, NAND becomes all-1.
- `WM_BASELINE_NAND`: ordinary explicit eBPF NAND baseline.

It also emits per-variant provenance (`<variant>.provenance.json`), a
per-variant verifier log, xlated disassembly of `wm_nand`, and an exhaustive
8-bit adder dataset. Re-check the eBPF evidence with `make verify`
(68149/68149, `semantic audit: ok`). Evidence files, the formal analysis
(A.9 abstraction-gap witness, A.10 opacity theorem), and the second witness
are catalogued in `ARTIFACT.md`.

This is not a verifier bypass, privilege escalation, or memory-corruption PoC.
It uses verifier-accepted bounded programs and offline `BPF_PROG_TEST_RUN`.

## Second Witness

The `witness2/` directory provides a structurally different witness in a
join-based interval analyzer: `python3 witness2/witness.py` runs the
self-contained analyzer, and `bash witness2/frama_c/run.sh` reproduces the
core result in Frama-C EVA. On Ubuntu 24.04, install Frama-C with
`sudo apt-get install -y frama-c-base`. The captured EVA result is in
`witness2/frama_c/RESULTS.md`.

Optional checks:

```sh
make verify-witness2
make verify-framac
```

## Outlook

Two directions extend this work beyond the present eBPF instance; they are
noted here as research bets, with honest tractability.

**1. From instances to a theorem — the sufficiency of abstraction gaps.**
The Opacity Theorem (Appendix A.10) is already a conditional theorem, but its
hypothesis — an *exploitable gap* — is today established by instances, not by a
structural characterization of the abstraction. The foundational target is to
turn "an abstraction-layer gap yields a programmable weird machine" into a
theorem with boundary conditions: *given what class of sound abstractions `α`
does a program-constructible `⊤`-channel necessarily arise, and when is it
necessarily exploitable?* That moves the result from "another instance" to a
citable theory result — the durable contribution is the framework, not any one
construction. The near-term empirical down-payment is now in `witness2/`: a
structurally different, join-based interval-analysis witness, with a Frama-C
EVA reproduction, showing that the phenomenon tracks sound-but-incomplete
abstraction rather than an eBPF quirk. The remaining high-ceiling target is a
structural theorem characterizing which abstractions necessarily admit such
channels.

**2. Weird machines in the neural-semantic layer.**
eBPF is an old concept on a new substrate; the largely unexplored direction is
the *abstraction gap between natural-language semantics and neural
computation*. As AI systems become infrastructure, that gap is a large and
expanding attack surface — indirect prompt injection is already the top OWASP
LLM risk. The high-stakes proposition is to show that such attacks are **not a
class of bugs but a necessary product of the abstraction gap, non-eliminable at
the semantic layer** — a claim whose real-world stakes exceed eBPF's, because
it concerns systems already deployed worldwide. The ceiling here is highest
(timing + stakes + open ground), but the bar is two open problems this artifact
does not touch: formalizing weird state over *probabilistic* systems, and
cross-turn error correction. Solving them is a separate — possibly more
important — paper.

