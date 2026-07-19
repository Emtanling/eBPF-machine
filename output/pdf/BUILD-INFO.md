# Public Technical-Report PDF Build Record

Status: **English and Chinese PDFs current for the 2026-07-20 Stock-R V2 /
EBRC U4 / CRL U6 release-reproduction sources**.

`PAPER_REPORT.pdf` and `PAPER_REPORT_ZH.pdf` were rendered in the authorized
Ubuntu/aarch64 VM from the current working-tree sources. pdfLaTeX and XeLaTeX
each completed two successful, halt-on-error passes. The final logs contain no
undefined references, errors, missing characters, rerun requests, runaway
arguments, or overfull boxes.

| Artifact | Source SHA-256 | PDF SHA-256 | Renderer | Pages / format |
|---|---|---|---|---|
| `PAPER_REPORT.pdf` | `d143e086197c418651fa6c77245ca700a8db0de4f0541a90234f753fa74ddd70` (`PAPER_REPORT.tex`) | `b3675f8eee55cb1b34f339749becea4f346bd45f32b7863bc20bbeee232f36c5` | pdfTeX 3.141592653-2.6-1.40.25 (TeX Live 2023/Debian), two passes | 16 pages, Letter |
| `PAPER_REPORT_ZH.pdf` | `36afa6afd4f0c5163b2d031dc4a022974e7ec465ea305b261aa857c9010dec2d` (`PAPER_REPORT_ZH.tex`) | `1ddef8603b11130c6aefd9066606df7e9fc19aae3105291cb7126ff0dadc0b48` | XeTeX 3.141592653-2.6-0.999995 (TeX Live 2023/Debian), two passes | 17 pages, A4 |

For the current English build, pages 1, 12, and 16 were rendered to PNG and
checked at full-page resolution after the final compile. For the current
Chinese build, pages 1, 12, 13, and 17 were rendered to PNG and checked at
full-page resolution after the final compile. The checked pages show no
clipping, overlap, unreadable glyphs, or footer intrusion. Long hash/certificate
values are preserved as full values split across short fixed-width lines;
complete machine-readable values are also preserved in the corresponding
evidence-bundle manifests and checker reports.

These attributed **public technical-report** PDFs are not anonymous submission
builds. The English PDF retains author identity, repository links, and the
AI-assistance disclosure; its conclusion begins on page 14, so it does not meet
a 12-page main-text constraint. Any venue submission requires a separately
reviewed anonymous and page-budgeted build.
