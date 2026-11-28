# GSEER v0.3.3-rc2 — Known Limitations (jujur, tanpa klaim berlebih)

1. **Cakupan pencarian = cakupan dataset.** GSEER adalah mesin
   pencari aset internet yang hasilnya bergantung pada dataset yang
   di-ingest dan di-index; search TIDAK otomatis memindai Internet.
   Index hanya berisi aset dari dataset yang Anda ingest (dataset
   terpusat proyek, import Anda sendiri, connector yang lolos review)
   atau korpus fixtures sintetis berlabel untuk evaluasi.
2. **Bukan FOFA/Shodan-equivalent.** Kami tidak mengklaim cakupan,
   frekuensi refresh, atau kedalaman data setara layanan pencarian
   aset internet komersial mana pun, tanpa bukti.
3. **Tiga status data — jangan tertukar.** (a) *Discovered* = aset
   muncul di dataset pasif yang di-ingest (`sources[]`,
   `first_seen`/`last_seen`, provenance `data_sources`); (b)
   *Resolved* = resolusi DNS hasil pemrosesan data ter-ingest; (c)
   *Actively observed* = HANYA dari `gseer scan` yang Anda jalankan
   sendiri di bawah scope sah (tabel `observations`, `scan_audits`).
   Baris di index tidak otomatis berarti aset diamati langsung oleh
   GSEER; tanpa dataset/scan Anda, index praktis kosong.
4. **PostgreSQL live green-path belum tervalidasi.** Source parity PG
   lengkap di kode (planner, migrasi, registry tests), tetapi jalur
   eksekusi PostgreSQL LIVE tidak pernah dijalankan di lingkungan
   pengembangan ini (tidak ada server PG). Mode personal (SQLite)
   adalah jalur yang sepenuhnya tervalidasi.
5. **Relevance default hanya untuk set ≤ 50.000 baris** (diukur dulu;
   set lebih besar jatuh ke recency + notice). Ranking tier
   exact/prefix/substring tidak terindeks — keputusan desain terukur,
   bukan keterbatasan tersembunyi.
6. **Data TLS/CT pada korpus bench/fixture adalah sintetis** (dibuat
   benchgen melalui projection yang sama dengan collectors — struktur
   nyata, bukan observasi Internet asli). Jangan baca output fixture
   sebagai hasil pemetaan Internet nyata.
7. **GSEER_HOME env leakage**: menjalankan `go test` dengan GSEER_HOME
   ter-set merusak isolasi beberapa test (first-run/profile). Suite
   dijalankan tanpa GSEER_HOME; CLI produksi tidak terdampak.
8. **Ini release candidate v0.3.3-rc2** (pending owner acceptance):
   perubahan breaking pada GQL/schema dapat terjadi hingga GA.
9. **Provider pdns free-tier dibatasi pihak provider.** Connector
   `pdns` (SOURCES §J) memakai antarmuka publik gratis HackerTarget dan
   Wayback CDX; kuota/rate limit ditentukan provider (pesan kuota
   HackerTarget diperlakukan sebagai error jujur, bukan data).  Untuk
   volume besar, operator menaikkan interval run atau mengurangi seed —
   GSEER tidak pernah me-render kuota sebagai data.
10. **Korpus `bench scale`/`bench quality` adalah SINTETIS** (generator
    deterministik, namespace example/RFC 1918/ASN privat).  Angka
    throughput/RAM/disk/latensi adalah pengukuran NYATA di mesin Anda
    melalui jalur import yang sama dengan dataset channel, tetapi isi
    korpusnya bukan observasi Internet — jangan dibaca sebagai cakupan.
11. **RSS pada bench adalah delta resident set** (VmRSS sebelum/sesudah),
    bukan peak; puncak termasuk cache SQLite.  Di non-Linux kolom RAM
    ditiadakan (0) — dilaporkan jujur per baris.

14. **Angka service = hasil dedup yang benar, bukan kehilangan.** Satu
    dataset dapat memuat dua record service untuk aset yang sama
    (contoh nyata di dataset v23: `wikipedia.org` dan `www.wikipedia.org`
    sama-sama resolve ke `198.35.26.224`, lalu keduanya diamati TLS
    :443). Import menggabungkan keduanya lewat kunci unik
    (asset, port, transport, protocol) → `port=443` melaporkan 17 baris
    dari 18 record. Ini perilaku dedup yang benar.
15. **Enrichment ip2asan bergantung egress.** Connector `ip2asn`
    (mapping IP→ASN via DNS cymru) berjalan best-effort: di lingkungan
    tanpa akses DNS eksternal ia menghasilkan 0 record (dicatat jujur
    di log run), di pipeline CI dengan egress normal ia menghasilkan
    puluhan record per run (bukti: 48 record di dataset v23).
