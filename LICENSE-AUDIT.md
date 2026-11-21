# LICENSE-AUDIT — GSEER v0.3.2 (MIT migration)

Audit seluruh dependency go.mod (direct + indirect).  Lisensi
pihak ketiga dibaca dari module cache sebagai bukti dan TIDAK
diubah.  Proyek sendiri kini MIT (lihat LICENSE &
docs/releases/LICENSE-MIGRATION-v0.3.2.md).

| Module | Versi | Peran | Lisensi | Bukti (module cache) |
|---|---|---|---|---|
| github.com/golang-migrate/migrate/v4 | v4.20.1 | direct | MIT | `github.com/golang-migrate/migrate/v4@v4.20.1/LICENSE` |
| github.com/jackc/pgerrcode | v0.0.0-20220416144525-469b46aa5efa | direct | MIT | `github.com/jackc/pgerrcode@v0.0.0-20220416144525-469b46aa5efa/LICENSE` |
| github.com/jackc/pgx/v5 | v5.12.0 | direct | MIT | `github.com/jackc/pgx/v5@v5.12.0/LICENSE` |
| github.com/spf13/cobra | v1.10.2 | direct | Apache-2.0 | `github.com/spf13/cobra@v1.10.2/LICENSE.txt` |
| github.com/spf13/pflag | v1.0.9 | direct | BSD-3-Clause | `github.com/spf13/pflag@v1.0.9/LICENSE` |
| golang.org/x/net | v0.62.0 | direct | BSD-3-Clause | `golang.org/x/net@v0.62.0/LICENSE` |
| gopkg.in/yaml.v3 | v3.0.1 | direct | MIT | `gopkg.in/yaml.v3@v3.0.1/LICENSE` |
| modernc.org/sqlite | v1.62.0 | direct | BSD-3-Clause | `modernc.org/sqlite@v1.62.0/LICENSE` |
| github.com/dustin/go-humanize | v1.1.0 | indirect | MIT | `github.com/dustin/go-humanize@v1.1.0/LICENSE` |
| github.com/google/uuid | v1.6.0 | indirect | BSD-3-Clause | `github.com/google/uuid@v1.6.0/LICENSE` |
| github.com/inconshreveable/mousetrap | v1.1.0 | indirect | Apache-2.0 | `github.com/inconshreveable/mousetrap@v1.1.0/LICENSE` |
| github.com/jackc/pgpassfile | v1.0.0 | indirect | MIT | `github.com/jackc/pgpassfile@v1.0.0/LICENSE` |
| github.com/jackc/pgservicefile | v0.0.0-20240606120523-5a60cdf6a761 | indirect | MIT | `github.com/jackc/pgservicefile@v0.0.0-20240606120523-5a60cdf6a761/LICENSE` |
| github.com/jackc/puddle/v2 | v2.2.3 | indirect | MIT | `github.com/jackc/puddle/v2@v2.2.3/LICENSE` |
| github.com/kr/text | v0.2.0 | indirect | MIT | `github.com/kr/text@v0.2.0/License` |
| github.com/mattn/go-isatty | v0.0.24 | indirect | MIT | `github.com/mattn/go-isatty@v0.0.24/LICENSE` |
| github.com/ncruces/go-strftime | v1.1.0 | indirect | MIT | `github.com/ncruces/go-strftime@v1.1.0/LICENSE` |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | indirect | BSD-3-Clause | `github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec/LICENSE` |
| github.com/rogpeppe/go-internal | v1.16.0 | indirect | BSD-3-Clause | `github.com/rogpeppe/go-internal@v1.16.0/LICENSE` |
| golang.org/x/sync | v0.24.0 | indirect | BSD-3-Clause | `golang.org/x/sync@v0.24.0/LICENSE` |
| golang.org/x/sys | v0.49.0 | indirect | BSD-3-Clause | `golang.org/x/sys@v0.49.0/LICENSE` |
| golang.org/x/text | v0.43.0 | indirect | BSD-3-Clause | `golang.org/x/text@v0.43.0/LICENSE` |
| modernc.org/libc | v1.80.1 | indirect | BSD-3-Clause | `modernc.org/libc@v1.80.1/LICENSE` |
| modernc.org/mathutil | v1.7.1 | indirect | BSD-3-Clause | `modernc.org/mathutil@v1.7.1/LICENSE` |
| modernc.org/memory | v1.12.1 | indirect | BSD-3-Clause | `modernc.org/memory@v1.12.1/LICENSE` |

Total module: 25;  UNKNOWN/NOT-IN-CACHE: 0.


---

## r3.1 — Copyright Holder Correction (96a9cf8)

Keputusan owner (disetujui): pemegang hak cipta proyek kini
**Copyright (c) 2026 Lutfifakee Project** pada seluruh atribusi MIT
proyek (LICENSE, 264 header source .go, Makefile, .goreleaser.yaml —
267 file, satu baris per file; bukti: CHANGED-FILES.txt,
DELTA-r3-to-r3.1.patch).

- `grep -rl 'The GSEER Authors' src/` → 0 file (evidence/goreleaser-verify.log).
- Lisensi tetap MIT penuh; teks AGPL tidak ada di LICENSE.
- Atribusi pihak ketiga di bawah ini TIDAK diubah (go.mod/go.sum
  identik; THIRD-PARTY-NOTICES.md identik dengan r3).
- Catatan historis AGPL (RELEASE_NOTES_v0.1.0.md,
  LICENSE-MIGRATION-v0.3.2.md) tetap utuh untuk menjelaskan sejarah
  lisensi (keduanya tanpa baris pemegang hak cipta proyek).


---

## r3.2 — Owner Acceptance Remediation (d0a1205)

- Holder `Copyright (c) 2026 Lutfifakee Project` tetap konsisten
  (LICENSE + seluruh header source + Makefile + .goreleaser.yaml +
  2 file regression test baru).
- Tabel dependency pihak ketiga di atas TIDAK berubah: go.mod/go.sum
  sha256 identik dengan paket r3.1 (diverifikasi otomatis pada
  acceptance r3.2); THIRD-PARTY-NOTICES.md identik.
- Catatan historis AGPL tetap utuh untuk sejarah lisensi.
