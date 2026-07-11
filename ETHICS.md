# Ethics and Safety

All experiments are intended for an isolated local VM. The artifact does not
attach programs to live network paths, does not target third-party systems, and
does not attempt privilege escalation, memory corruption, or verifier bypass.

The eBPF construction uses legal helper calls and bounded execution to study
the gap between verifier-level abstractions and runtime map metadata
transitions. The numeric precision control is offline static-analysis material: a local
Python interval interpreter and a Frama-C EVA run over a small C model. It does
not access third-party systems, secrets, or live targets.

The work is defensive in orientation: it characterizes a precision boundary
in one Linux eBPF verifier report so analyzer designers can state and test
which semantic relations their boundary intends to certify. It does not infer
whole-verifier unsoundness, a verifier bypass, or a vulnerability from that
local report-level uncertainty.
