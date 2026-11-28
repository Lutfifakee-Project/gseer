# GSEER v0.3.3 — Troubleshooting & Selfcheck

## Diagnosis cepat
1. `./bin/gseer version` — harus mencetak `gseer v0.3.3-rc2` (commit dan
   built_at dicetak juga; `unknown` normal untuk build lokal `make build`).
2. `./bin/gseer selfcheck` — menjalankan invarian index/proyeksi/
   preset. Semua baris harus `[ ok ]`; baris `FAIL` menunjukkan index
   korup → hapus `$(GSEER_HOME)/gseer.db` (backup dulu bila berisi data
   Anda) lalu `gseer setup` ulang.
3. `./bin/gseer setup` — migrasi schema; output `[ ok ] migrations:
   schema at head v15 (AT_HEAD)` berarti inisialisasi selesai
   (v15 = versi head logis yang dicetak CLI; file migrasi internal
   bernomor lebih granular). Jalankan ulang kapan saja; aman
   (idempotent).

## Variabel lingkungan
- `GSEER_HOME` — lokasi home GSEER (default `~/.gseer`). Semua state
  personal (gseer.db, config.yaml, cursor) ada di sini.
- `GSEER_PROFILE` — profil konfigurasi alternatif.
- **Jangan men-set `GSEER_HOME` saat menjalankan `go test`** — merusak
  isolasi test (first-run/profile). Suite dirancang dijalankan tanpa
  variabel ini.

## Error umum
- `E_SOURCE_TERMS` — connector/`data_sources` diaktifkan padahal
  verdict review-nya bukan `reviewed-enabled` (lihat docs/SOURCES.md).
  Perbaikan: matikan sumber tersebut atau turunkan verdict-nya; runner
  menolak sumber tanpa review — ini desain, bukan bug.
- Dataset manifest gagal diunduh/diparse — `gseer dataset update`
  mengunduh manifest terpusat dan **memverifikasi tanda tangan Ed25519**
  terhadap keyring yang tertanam di binary (`internal/dataset/sign.go`):
  manifest tanpa tanda tangan / kunci asing / yang diubah DITOLAK
  sebelum payload diunduh (`E_DATASET_UNSIGNED` / `E_DATASET_UNKNOWN_KEY`
  / `E_DATASET_BAD_SIGNATURE`); checksum payload diverifikasi setelahnya
  (`E_DATASET_CHECKSUM`).  Bidang manifest tambahan yang tidak dikenal
  mengubah bytes kanonik dan membuat verifikasi tanda tangan gagal —
  bukan diabaikan.  Detail kebijakan: docs/DATASET.md §5-§6.
  Bila unduh gagal (offline), setup tetap lanjut dengan local discovery;
  ulangi `gseer dataset update` saat online.
- Query "0 result(s)" padahal index terisi — cakupan = dataset yang
  di-ingest; periksa `gseer setup --load-fixtures` untuk evaluasi,
  atau ingest dataset Anda (docs/DATASET.md, docs/IMPORT-FORMAT.md).
  Ingat: tanpa dataset/scan, index kosong.
- Relevance "bukan exact dulu" pada set besar — set matched > 50.000
  baris jatuh ke recency + notice; paksa ranking dengan
  `--sort relevance:asc`.
- Build gagal: pastikan Go 1.26+ (`go version`); tidak perlu CGO untuk
  mode personal (SQLite embedded modernc).
- Database terkunci (SQLite): satu proses `gseer` aktif per file DB
  pada saat operasi tulis; hentikan proses lain yang memakai
  GSEER_HOME yang sama.

## Mode PostgreSQL
Source parity lengkap di kode, tetapi jalur eksekusi PG LIVE belum
pernah tervalidasi oleh pengembangan (lihat KNOWN-LIMITATIONS.md §4).
Konfigurasi: docs/CONFIG.md + docs/DEPLOYMENT.md; gunakan migrasi
yang sama. Laporkan hasil PG Anda sebagai temuan, bukan asumsi.

## Verifikasi paket (bila hasil tidak sesuai README-RELEASE)
1. `sha256sum -c SHA256SUMS.txt` di dalam paket — 456 berkas harus OK.
2. Bandingkan `./bin/gseer version` dengan identitas di
   RELEASE-MANIFEST.md — harus sama (v0.3.3-rc2).
3. Bila checksum tidak cocok: paket rusak saat transfer — unduh ulang;
   jangan patch manual.
