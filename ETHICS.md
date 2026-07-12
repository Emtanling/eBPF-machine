# Ethics and Safety

All experiments are intended for an isolated local VM. The artifact does not
attach programs to live network paths, does not target third-party systems, and
does not attempt privilege escalation, memory corruption, or verifier bypass.

The eBPF construction uses legal helper calls and bounded execution to study
post-acceptance, state-mediated runtime semantics and the evidence required to
relate them to a recognizer report. The numeric precision control is offline static-analysis material: a local
Python interval interpreter and a Frama-C EVA run over a small C model. It does
not access third-party systems, secrets, or live targets.

The work is defensive in orientation: it records acceptance (A), establishes a
same-suffix causal state distinction (C), and supports bounded programmability
(P) under explicit implementation premises. It does not extract Linux computed
report cells and therefore does not establish report-relative non-factorization
(R), whole-verifier unsoundness, a verifier bypass, a vulnerability, or a
policy-level weird machine (W).
