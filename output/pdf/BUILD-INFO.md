# Public Technical-Report PDF Build Record

Status: **English and Chinese PDFs current for the 2026-07-20 Stock-R V2 /
EBRC U4 / CRL U6 and weird-machine retrospective sources**.

`PAPER_REPORT.pdf` and `PAPER_REPORT_ZH.pdf` were rendered in the authorized
Ubuntu/aarch64 VM from the current working-tree sources. XeLaTeX completed two
successful, halt-on-error passes for each document. The final logs contain no
undefined references, citation errors, rerun requests, overfull boxes, or build
errors. Expected IEEEtran/font-substitution and underfull-box warnings remain.

| Artifact | Source SHA-256 | PDF SHA-256 | Renderer | Pages / format |
|---|---|---|---|---|
| `PAPER_REPORT.pdf` | `863f4b8f3dd6a3a4b5ca0a780b4e17e0474f9f351cf11893681fdfa09b901794` (`PAPER_REPORT.tex`) | `1a5c15fe81f9165b452fe408de8d42a9db67fa8a3f9868466872af307c2b527d` | XeTeX 3.141592653-2.6-0.999995 (TeX Live 2023/Debian), two passes | 19 pages, Letter |
| `PAPER_REPORT_ZH.pdf` | `717e689f94b129d729d1528572e133031bfa63e97b00e26a434752a0eff9de9c` (`PAPER_REPORT_ZH.tex`) | `93d02e061a4325e81e28b718f7330cc07631f4bb4a0a774904961bc0ff2a56b6` | XeTeX 3.141592653-2.6-0.999995 (TeX Live 2023/Debian), two passes | 18 pages, A4 |

The English first page and pages 15--17, including the classification lattice,
the nine-family retrospective table, conclusion, and data-availability text,
were rendered to PNG and visually checked after the final compile. The Chinese
first page, pages 8--9, and pages 15--18, including the complete 5.1--5.8
evaluation numbering, multi-page retrospective table, conclusion,
data-availability text, disclosure, and bibliography-source note, were likewise
checked. No clipping, overlap, unreadable glyphs, or footer intrusion was
observed.

Text extraction confirms Proposition 4, the IA32 page-fault classification,
PCC, TrueType and FORCEDENTRY/JBIG2, cross-language/DOPPLER coverage, the exact
`EXACT_STOCK_R_V2_QUERY` boundary, and the no-eBPF-weird-machine conclusion in
both language builds. All 54 English bibliography items are cited and every
citation key resolves. On the VM, `make reproduce-paper` returned
`all_expected=true` and `unexpected_results=0`; `make test-stock-r-tools`
passed 172 tests.

These attributed **public technical-report** PDFs are not anonymous submission
builds. They retain author identity, repository links, and the AI-assistance
disclosure. Any venue submission still requires a separately reviewed anonymous
and page-budgeted build.
