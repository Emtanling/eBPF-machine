# Ethics and Safety

All experiments are intended for an isolated local VM. The artifact does not
attach the evaluated programs to production network paths, does not target
third-party systems, and does not attempt privilege escalation, memory
corruption, or verifier bypass. The stock-Linux capture briefly attaches an
fexit observer to verifier-internal functions during an isolated program load;
the observer records verifier decisions and does not alter the accepted
program's execution.

The eBPF construction uses legal helper calls and bounded execution to study
post-acceptance, state-mediated runtime semantics and the evidence required to
relate them to a recognizer report. It does not access third-party systems,
secrets, or live targets.

The work is defensive in orientation. The `wm_circuit` carrier records
acceptance (A), gives a conditional same-suffix causal state distinction (C),
and supports bounded programmability (P) under explicit implementation
premises, but does not establish R or W. A distinct frozen stock-Linux
`rac_single` tuple records an operational prune event and two same-suffix
samples. Its legacy adapter constructs a finite model with a factorization
failure, but the current evidence-bounded assessment is `UNKNOWN` because the
observed outcomes have no must-outcome proof. This is not a claim about a
documented Linux functional-report contract. A second, auxiliary
custom-report tuple independently establishes R only on its own restricted
carrier. The stock-Linux observations and the auxiliary R carrier are not
combined with `wm_circuit`, and the work
establishes neither whole-verifier unsoundness, a verifier bypass, a
vulnerability, W, nor a complete weird machine.
