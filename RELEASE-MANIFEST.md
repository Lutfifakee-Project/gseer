# GSEER v0.3.3-rc2 — Release Manifest

| Item | Nilai |
|---|---|
| Produk | GSEER — mesin pencari aset internet berbasis GQL |
| Identitas | **v0.3.3-rc2** (CLI `gseer version`, Makefile default VERSION, CHANGELOG, nama arsip) |
| Jenis paket | Official release candidate — **sumber produk lengkap**, bukan patch/kit/checkpoint |
| Arsip | `gseer-v0.3.3-rc2-docfix2.zip` (kandidat rilis final — dibangun di atas v0.3.3-rc1 yang di-accept owner + remediasi rilis ter-audit, tanpa ZIP checkpoint; docfix1 = revisi dokumentasi atas temuan Owner Acceptance RC2; docfix2 = remediasi jalur instalasi RC atas blocker Owner — tag `v0.3.3-rc2` belum ada, jalur resmi RC = ZIP → verifikasi SHA-256 → extract → `make build` → verify version, dipisah dari jalur `go install` versi bertag — identitas produk tetap v0.3.3-rc2, tanpa perubahan source/behavior) |
| Checksum luar | `gseer-v0.3.3-rc2-docfix2.zip.sha256` (di folder distribusi) |
| Checksum dalam | `SHA256SUMS.txt` — daftar per-berkas seluruh isi paket |
| Provenance | v0.3.3-rc1 (owner-accepted baseline) + v0.3.3-rc2 remediasi rilis R01–R06: bentuk command resmi + contoh search terverifikasi pada fixture, audit referensi versi, kode error docs = implementasi (sign.go + fetch.go), pin instalasi eksplisit, fix output status "vv" + unit test kunci format; + docfix1 revisi docs (judul Quickstart rc2, pin instalasi, provenance dataset channel); + docfix2 remediasi jalur instalasi RC (ZIP → make build sebagai jalur resmi prerelease; `go install @<tag>` dipisah untuk versi bertag; hitung SHA256SUMS dikoreksi 455→456); Ed25519 verify (anchor 5355d8197f5222d0), retry+backoff+Range-resume, E_DATASET_DOWNGRADE gate + dataset history, connector `pdns` (SOURCES §J), coverage metrics, `bench scale`/`bench quality` dibawa utuh dari rc1. Bukti: go test 27 paket ok, race 0, kompatibilitas 9/9, dataset LIVE v25 |
| Dataset channel | `central-dataset` (rolling, v25 per 2026-11-28 — live check `gseer dataset check`; v23 adalah observasi era rc1 2026-11-27) — TIDAK di-bundel; diunduh+diverifikasi otomatis saat `gseer dataset update` |
| Lisensi | AGPL-3.0 (lihat LICENSE) |

## Struktur paket
- `gseer-v0.3.3-rc2/` — tree sumber produk (cmd/, internal/, docs/,
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
- `Makefile`: `VERSION ?= v0.3.3-rc2` → `make build` mencetak
  `gseer v0.3.3-rc2`
- `CHANGELOG.md`: entri "[v0.3.3-rc2] — release remediation (docs & status output)"
- `README-RELEASE.md`, `RELEASE-MANIFEST.md`,
  `KNOWN-LIMITATIONS.md`: identitas sama (`v0.3.3-rc2`);
  `OWNER-ACCEPTANCE-REPORT.md` dipertahankan apa adanya sebagai
  rekaman acceptance v0.3.3-rc1 (Owner Acceptance untuk rc2 adalah
  gate SETELAH paket selesai)
- Validasi integritas dijalankan TERHADAP arsip final (unzip →
  SHA256SUMS per-berkas → build dari arsip → version/status/doctor);
  hasil tercatat di GSEER-v0.3.3-rc2-PACKAGING-REPORT.md
