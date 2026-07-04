# Ethics and Safety

All experiments are intended for an isolated local VM. The artifact does not
attach programs to live network paths, does not target third-party systems, and
does not attempt privilege escalation, memory corruption, or verifier bypass.

The construction uses legal helper calls and bounded execution to study the gap
between verifier-level abstractions and runtime map metadata transitions.
