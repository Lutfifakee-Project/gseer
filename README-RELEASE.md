# GSEER v0.3.3-rc2 — Official Release Candidate (README RELEASE)

GSEER adalah mesin pencari aset internet berbasis GQL yang berjalan
personal/local (SQLite) dengan backend PostgreSQL sebagai opsi. Paket
ini dibangun dari v0.3.3-rc1 yang telah di-accept owner, ditambah
remediasi rilis ter-audit R01–R06 (bentuk command resmi + fix output
`status`; lihat `CHANGELOG.md` entri `[v0.3.3-rc2]`), revisi
dokumentasi docfix1 atas temuan Owner Acceptance (judul Quickstart,
pin instalasi eksplisit, provenance dataset channel), dan revisi
docfix2 atas blocker instalasi Owner Acceptance docfix1: tag Git
`v0.3.3-rc2` belum ada, sehingga seluruh dokumen kini memisahkan
jalur RC prerelease (ZIP → verifikasi SHA-256 → extract → `make
build` → verify version) dari jalur `go install` yang hanya berlaku
untuk versi yang SUDAH memiliki tag — satu arsip
mandiri berisi sumber produk lengkap; tidak ada patch atau kit
tambahan yang perlu diterapkan.

## Prasyarat
- Go **1.26+** (toolchain resmi; `go version` untuk cek)
- `make` + `unzip` + `sha256sum` (GNU coreutils)
- SQLite embedded (tanpa server DB; tanpa Docker untuk mode personal)

## Instalasi & verifikasi (alur resmi)
```bash
# 0. cek integritas paket
sha256sum -c gseer-v0.3.3-rc2-docfix2.zip.sha256 # di folder distribusi
unzip gseer-v0.3.3-rc2-docfix2.zip && cd gseer-v0.3.3-rc2

# 1. install/build (versi tercetak otomatis = v0.3.3-rc2)
make build

# 2. verify version
./bin/gseer version          # harus mencetak: gseer v0.3.3-rc2

# CATATAN JALUR (docfix2): ini adalah jalur PRERELEASE RC — tag Git
# v0.3.3-rc2 belum ada, jadi `go install …@v0.3.3-rc2` TIDAK tersedia
# ("invalid version: unknown revision"), `@latest` hanya me-resolve tag
# non-prerelease, dan `go install ./cmd/gseer` jujur mencetak
# `gseer dev`.  `go install github.com/Lutfifakee-Project/gseer/
# cmd/gseer@<tag>` adalah jalur untuk versi yang SUDAH memiliki tag
# (saat ini tertinggi: v0.3.3-rc1) — bukan untuk memasang RC2.

# 2b. (RC2) jalur dataset kini WAJIB bertanda tangan Ed25519 — manifest
#     live diverifikasi terhadap keyring yang tertanam di binary
#     (anchor 5355d8197f5222d0, terbukti terhadap channel produksi v23).
#     Manifest unsigned / kunci asing / manifest yang diubah = ditolak
#     (E_DATASET_UNSIGNED / E_DATASET_UNKNOWN_KEY / E_DATASET_BAD_SIGNATURE)
#     sebelum payload diunduh; checksum payload tetap diverifikasi
#     setelahnya (E_DATASET_CHECKSUM).

# 3. setup & inisialisasi (personal mode: satu file SQLite lokal)
./bin/gseer setup            # membuat ~/.gseer (GSEER_HOME), migrasi
                             # schema ke head (saat ini head v15;
                             # doctor mencetak versinya)

# 4. search — index terisi dari DATASET; untuk evaluasi, muat
#    korpus fixtures sintetis berlabel:
./bin/gseer setup --load-fixtures
./bin/gseer search 'product CONTAINS "OpenSSH"'
./bin/gseer search 'product CONTAINS "OpenSSH"' --sort relevance:asc   # paksa ranking (flag di LUAR kutip GQL)
./bin/gseer search 'product *= "OpenSSH"'      # wildcard
./bin/gseer search 'tls.version != ""'         # TLS (bila data TLS ada)
./bin/gseer search 'ct.entry_type != ""'       # CT (bila data CT ada)

# 5. metrik cakupan & kualitas (v0.3.3)
./bin/gseer coverage          # aset unik per kind, negara/ASN, umur data,
                              # status per sumber (aktif/stale/gagal/tak-tersedia),
                              # duplikasi lintas sumber — dari index NYATA
./bin/gseer dataset history   # riwayat versi dataset yang pernah diimpor
./bin/gseer bench scale       # throughput import NYATA + RAM/disk + latensi
                              # search pada skala 1x/10x/100x (korpus sintetis)
./bin/gseer bench quality     # akurasi P/R/F1 terhadap ground-truth berlabel

# 6. verification & troubleshooting
./bin/gseer selfcheck         # invarian index/proyeksi/presets
go test ./internal/...        # test suite lengkap (tanpa GSEER_HOME)
make bench-baseline BENCH_ASSETS=2000 BENCH_RUNS=2   # opsional: gate performa
make bench-check BENCH_ASSETS=2000 BENCH_RUNS=2
```

## Data: ingestion, collector, dan siklus hidup aset
GSEER TIDAK memindai Internet otomatis. Index terisi melalui tiga
jalur yang berbeda statusnya:

1. **Discovered (pasif)** — aset masuk dari dataset yang Anda ingest:
   dataset terpusat proyek (unduh-verifikasi-import; sejak v0.3.3:
   retry+backoff, resume Range, deteksi downgrade, riwayat versi;
   lihat `docs/DATASET.md`), format import Anda sendiri
   (`docs/IMPORT-FORMAT.md`), atau connector yang lolos review
   (`docs/SOURCES.md`; v0.3.3 menambah lapisan passive DNS — §J).
   Provenance tersimpan per-aset (`sources[]`,
   `first_seen`/`last_seen`, tabel `data_sources`).
2. **Resolved** — resolusi DNS hasil pemrosesan data yang di-ingest
   (tercatat pada proyeksi core/evidence-quality; bukan pengamatan
   langsung oleh GSEER).
3. **Actively observed** — HANYA jika Anda menjalankan observasi
   aktif sendiri di bawah scope yang sah: `gseer scope` + `gseer
   scan` (HTTP/TLS; lihat `docs/SCANNING.md`; jejak di tabel
   `observations`/`scan_audits`, migrasi 0018).

Untuk evaluasi tanpa data nyata: `--load-fixtures` memuat korpus
sintetis berlabel (struktur nyata, konten bukan observasi Internet).

## Peta dokumen
- Install/quickstart: `docs/INSTALL.md`, `docs/QUICKSTART.md`
- Konfigurasi: `docs/CONFIG.md`
- Sintaks pencarian: `docs/SEARCH-SYNTAX.md`
- Dataset & import: `docs/DATASET.md`, `docs/IMPORT-FORMAT.md`,
  `docs/SOURCES.md`, `docs/SCANNING.md`
- Benchmark: `docs/BENCHMARKING.md`
- Deployment/PG/Docker: `docs/DEPLOYMENT.md`, `docs/DOCKER.md`
- **Troubleshooting & selfcheck: `docs/TROUBLESHOOTING.md`**
- Batasan: `KNOWN-LIMITATIONS.md` · Manifest: `RELEASE-MANIFEST.md`
  · Acceptance: `OWNER-ACCEPTANCE-REPORT.md` · Riwayat:
  `CHANGELOG.md`
