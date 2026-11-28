# GSEER v0.3.3-rc1 — Release Manifest

| Item | Nilai |
|---|---|
| Produk | GSEER — mesin pencari aset internet berbasis GQL |
| Identitas | **v0.3.3-rc1** (CLI `gseer version`, Makefile default VERSION, CHANGELOG, nama arsip) |
| Jenis paket | Official release candidate — **sumber produk lengkap**, bukan patch/kit/checkpoint |
| Arsip | `gseer-v0.3.3-rc1.zip` (SATU kandidat rilis final — dibangun di atas rc2 yang di-accept, tanpa ZIP checkpoint) |
| Checksum luar | `gseer-v0.3.3-rc1.zip.sha256` (di folder distribusi) |
| Checksum dalam | `SHA256SUMS.txt` — daftar per-berkas seluruh isi paket |
| Provenance | RC2 (owner-accepted baseline) + v0.3.3-rc1: Ed25519 verify (anchor 5355d8197f5222d0), retry+backoff+Range-resume download, E_DATASET_DOWNGRADE gate + dataset history, connector `pdns` (SOURCES §J: HackerTarget + Wayback CDX), coverage metrics (status sumber, duplikasi lintas sumber, umur data, per negara/ASN), `bench scale` (import/RAM/disk/latensi 1x-100x) + `bench quality` (ground-truth P/R/F1), bukti search mastery + konsistensi JSON/CSV/NDJSON |
| Dataset channel | `central-dataset` (rolling, v23 per 2026-11-27) — TIDAK di-bundel; diunduh+diverifikasi otomatis saat `gseer dataset update` |
| Lisensi | AGPL-3.0 (lihat LICENSE) |

## Struktur paket
- `gseer-v0.3.3-rc1/` — tree sumber produk (cmd/, internal/, docs/,
  deploy/, pipeline/, scripts/, Makefile, go.mod, Dockerfile, dll)
- `README-RELEASE.md` — instruksi resmi unzip → build → verify →
  setup → search → verification + peta seluruh dokumen
- `KNOWN-LIMITATIONS.md` — batasan jujur produk (termasuk
  distinksi discovered/resolved/actively-observed)
- `RELEASE-MANIFEST.md` — dokumen ini
- `OWNER-ACCEPTANCE-REPORT.md` — bukti acceptance + validasi paket
- `docs/` — INSTALL, QUICKSTART, CONFIG, SEARCH-SYNTAX, DATASET,
  IMPORT-FORMAT, SOURCES, SCANNING, BENCHMARKING, DEPLOYMENT,
  DOCKER, RELATIONS, RULES, UPDATE, **TROUBLESHOOTING (baru)**, dll

## Kebersihan paket (dikecualikan dari arsip)
- Artefak build: `bin/`, biner `benchgen` (direproduksi via `make build`
  / `go run ./internal/bench/benchgen`)
- Data: `*.db`, `*.db-wal`, `*.db-shm`, korpus/korpus-lama
- VCS: `.git`; sisa patch/kit/checkpoint/recovery lama
- Pemindaian dilakukan: tidak ada file database/log/patch/biner/seed
  kredensial di dalam paket (scan otomatis saat packaging)

## Konsistensi identitas (diverifikasi saat packaging)
- `Makefile`: `VERSION ?= v0.3.3-rc1` → `make build` mencetak
  `gseer v0.3.3-rc1`
- `CHANGELOG.md`: entri "[v0.3.3-rc1] — resilient pipeline, layered sources, measured quality"
- `README-RELEASE.md`, `RELEASE-MANIFEST.md`,
  `OWNER-ACCEPTANCE-REPORT.md`, `KNOWN-LIMITATIONS.md`: identitas sama
- Validasi 12 langkah dijalankan TERHADAP arsip final (bukan hanya
  working directory) — hasil tercatat di OWNER-ACCEPTANCE-REPORT.md §2
