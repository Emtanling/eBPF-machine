# Ethics and Safety

All experiments are intended for an isolated local VM. The artifact does not
attach programs to live network paths, does not target third-party systems, and
does not attempt privilege escalation, memory corruption, or verifier bypass.

The eBPF construction uses legal helper calls and bounded execution to study
the gap between verifier-level abstractions and runtime map metadata
transitions. The second witness is offline static-analysis material: a local
Python interval interpreter and a Frama-C EVA run over a small C model. It does
not access third-party systems, secrets, or live targets.

The work is defensive in orientation: it characterizes a structural blind spot
of sound verifiers so analyzer designers can reason about it.
