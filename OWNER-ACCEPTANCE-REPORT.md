# GSEER v0.3.3-rc1 — Owner Acceptance Report

## 1. Status acceptance
- **v0.3.2-rc2: di-accept owner** (rehearsal 8/8 PASS dari byte ZIP,
  sesi 2026-11-27) — baseline paket ini.
- Paket ini adalah **kandidat rilis final v0.3.3-rc1**: rc2 + enam blok
  persyaratan mandat yang diperluas (metrik cakupan, sumber berlapis,
  search matang, pipeline tahan gangguan, kualitas terukur, acceptance
  kondisi nyata) — SATU arsip, tanpa ZIP checkpoint.
- **Release approval tetap keputusan owner** setelah acceptance pribadi
  owner lolos; paket berstatus READY FOR OWNER ACCEPTANCE.

## 2. Dua blocker audit sebelumnya — status di kode v0.3.3-rc1
1. **Verifikasi Ed25519 manifest sebelum dataset dipercaya** — FIXED dan
   dipertahanan: `FetchManifest` → `VerifyTrusted` (keyring tertanam,
   anchor `5355d8197f5222d0`, terbukti byte-exact terhadap channel LIVE
   v23) SEBELUM URL payload diresolusi; import meng-verifikasi ulang.
   Bukti negatif segar: manifest yang diubah satu karakter → ditolak
   fail-closed (scripts/v033-acceptance.sh §G).
2. **Laporan migrasi v15 (head v14)** — root cause diperbaiki sejak RC2
   (selfcheck/doctor backend-aware `GetMigrationStatus`, pinned oleh
   `internal/cli/rev14_regression_test.go`); di v0.3.3-rc1 seluruh alur
   melaporkan konsisten `v15 (head v15)` — bukti segar: setup bersih +
   selfcheck pada byte arsip (§3).

## 3. Validasi kondisi nyata — driver resmi `scripts/v033-acceptance.sh`
Driver menjalankan alur wajib pada home terisolasi: build → vet →
`make build` → identity → setup bersih → **dataset update LIVE
(GitHub, signature+checksum)** → status → search → export (json/csv/
ndjson + uji konsistensi jumlah baris) → selfcheck → update ke-2
(no-op, tanpa duplikasi) → dataset history → coverage (JSON: status
sumber, duplikasi lintas sumber, umur data) → bench scale/quality →
negatif (network mati → `E_DATASET_UNREACHABLE`; manifest tamper →
signature refusal; payload corrupt → `E_DATASET_CHECKSUM`, DB utuh) →
restart + search → jalur `env -i` + cwd=`/` (bebas environment GLM) →
`go test ./...` penuh → `-race` pada paket yang berubah.

Hasil eksekusi terakhir dicetak di log driver; ringkasan PASS/FAIL
per langkah tercatat di `VALIDATION-LOG.txt` folder distribusi.

## 4. Perubahan v0.3.2-rc2 → v0.3.3-rc1 (ringkas)
- **R4 pipeline**: retry+backoff (429/5xx/transport), resume download
  HTTP Range (checksum atas artifact lengkap), `E_DATASET_DOWNGRADE`
  eksplisit, `dataset history` — semua dengan test penuh.
- **R2 sumber berlapis**: connector `pdns` (HackerTarget hostsearch +
  Wayback CDX; docs/SOURCES.md §J) — registry 10 connector.
- **R1 metrik**: `coverage` kini melaporkan distinct ports/protocols/
  ASN org, observasi per kind, umur data, status per sumber (aktif ≤7d/
  stale/failed/not_available), duplikasi lintas sumber + contoh top,
  per negara/ASN — dari index nyata.
- **R3 search**: bukti berlabel field/operator/relevance/cross-entity/
  pagination/sort/limit + konsistensi JSON/CSV/NDJSON (row set identik).
- **R5 kualitas**: `bench scale` (import nyata 1x/10x/100x: wall time,
  rows/s, DB bytes, RSS delta, p50/p95) + `bench quality` (ground-truth
  P/R/F1) + test kebocoran antar-store.

## 5. Bukti eksekusi yang terakumulasi (rc2, dipertahankan di rc1)
- Ed25519: anchor produksi `5355d8197f5222d0` terbukti byte-exact
  terhadap manifest LIVE v23 SEBELUM di-embed; keyring juga memuat
  anchor generasi sebelumnya `7b3879ab7a423772` (masa rotasi). 9
  negative test signature + tamper refusal terbukti.
- Ekspansi dataset owner-authorized: seed register 14 → 26 domain
  (DNS-only), CT budget 2000 → 4000/run; koleksi nyata lokal 557
  assets / 559 obs (CT 269, DNS 259, PTR 31; ip2asan 0 di sandbox tanpa
  egress — jujur; referensi CI: 48 di v23).
- Channel LIVE: v23 lolos signature+checksum → 343 obs; `port=443` =
  17 baris (dedup benar: 18 record, 2 aset sama `198.35.26.224`).
- Toolchain Go 1.26.11; module cache dibangun ulang via `go mod
  download` publik (go.sum mengikat seluruh dependensi).

## 6. Kejujuran produk (rinci di KNOWN-LIMITATIONS.md)
- GSEER = mesin pencari aset internet; hasil = dataset yang di-ingest
  dan di-index; TIDAK memindai Internet otomatis; tidak ada klaim
  FOFA/Shodan-equivalent.
- Distinksi data: *discovered* / *resolved* / *actively observed*.
- Korpus `bench scale`/`bench quality` SINTETIS (pengukurannya nyata).
- Provider `pdns` free-tier dibatasi provider; kuota = error jujur.
- PostgreSQL live green-path belum tervalidasi (limitasi lingkungan).

## 7. Verdict
- Paket: `gseer-v0.3.3-rc1.zip` · checksum: `gseer-v0.3.3-rc1.zip.sha256`
- **RELEASE CANDIDATE SIAP UNTUK OWNER ACCEPTANCE.** Tidak ada
  commit/push/tag/publikasi; official release menunggu otorisasi
  eksplisit owner.
