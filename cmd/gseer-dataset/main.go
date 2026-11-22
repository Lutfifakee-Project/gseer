// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// gseer-dataset — the maintainer-side companion that builds, signs, and
// validates the CENTRAL INTERNET-ASSET DATASET (P0-1: signed central
// dataset distribution).
//
//	gseer-dataset keygen -out SEED_FILE
//	    generate a new Ed25519 signing keypair: the 32-byte private seed
//	    goes to SEED_FILE (0600 — keep it in the CI secret store, NEVER
//	    in the repository), the public half + key ID print for embedding
//	    into internal/dataset/keys.go (docs/DATASET.md §5).
//	gseer-dataset build -db STAGING.db -out DIST_DIR -version N
//	    export the staging Local Index's validated evidence as the
//	    dataset payload (NDJSON.gz) + manifest (version, checksums,
//	    provenance, observed_at bounds, freshness).  Fixture rows and
//	    previous import bookkeeping rows are EXCLUDED; every record is
//	    validated (schema, asset/service sanity, observed_at window,
//	    provenance) — an invalid record FAILS the build.  Signing key
//	    via -key-file or GSEER_DATASET_SIGNING_KEY — without it the
//	    manifest stays UNSIGNED and the pipeline gate will refuse it.
//	gseer-dataset sign -dir DIST_DIR -key-file SEED_FILE
//	    sign the manifest with the private seed (the same key whose
//	    public half the CLI embeds); the signature binds the canonical
//	    manifest core — including the payload sha256/size/records.
//	gseer-dataset validate -dir DIST_DIR
//	    re-verify a built artifact: manifest schema, SIGNATURE against
//	    the trusted keyring, payload checksum, record count, per-record
//	    validation.  The pipeline refuses to publish without a passing
//	    validate — an unsigned artifact cannot pass.
//
// End-user machines never need this binary: the `gseer` CLI downloads
// and imports the published dataset (gseer dataset update / gseer setup).
package main

import (
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Lutfifakee-Project/gseer/internal/dataset"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gseer-dataset: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "build":
		buildCmd(os.Args[2:])
	case "sign":
		signCmd(os.Args[2:])
	case "keygen":
		keygenCmd(os.Args[2:])
	case "validate":
		validateCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gseer-dataset — central dataset builder/signer/validator (docs/DATASET.md)

  gseer-dataset keygen   -out SEED_FILE
  gseer-dataset build    -db STAGING.db -out DIST_DIR -version N [-key-file SEED_FILE]
  gseer-dataset sign     -dir DIST_DIR -key-file SEED_FILE
  gseer-dataset validate -dir DIST_DIR
`)
}

type buildOptions struct {
	dbPath    string
	outDir    string
	version   int64
	generated string
	keyFile   string
}

// stagingRow is one raw evidence row from the staging export query.
type stagingRow struct {
	id                                     int64
	observedAtRaw, payloadHash, provenance string
	evidenceRaw                            string
	sourceName, sourceConnector            string
	kind, value                            string
	ip, domain, host                       sql.NullString
	asn                                    sql.NullInt64
	asnOrg, geoCountry, geoRegion, geoCity sql.NullString
	sources                                string
	svcPort                                sql.NullInt64
	svcTransport, svcProtocol              sql.NullString
	svcName, svcProduct, svcVersion        sql.NullString
}

// scanStagingRow scans one export row.
func scanStagingRow(rows *sql.Rows) (*stagingRow, error) {
	r := &stagingRow{}
	err := rows.Scan(&r.id, &r.observedAtRaw, &r.payloadHash, &r.provenance, &r.evidenceRaw,
		&r.sourceName, &r.sourceConnector,
		&r.kind, &r.value, &r.ip, &r.domain, &r.host,
		&r.asn, &r.asnOrg, &r.geoCountry, &r.geoRegion, &r.geoCity, &r.sources,
		&r.svcPort, &r.svcTransport, &r.svcProtocol, &r.svcName, &r.svcProduct, &r.svcVersion)
	return r, err
}

// buildSummary folds the export stream into the manifest numbers.
type buildSummary struct {
	total     int64
	assets    map[string]bool
	services  int64
	oldest    time.Time
	newest    time.Time
	perSource map[string]*dataset.ProvenanceSummary
}

func buildCmd(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	opts := &buildOptions{}
	fs.StringVar(&opts.dbPath, "db", "", "staging personal SQLite Local Index to export (required)")
	fs.StringVar(&opts.outDir, "out", "", "output directory for the artifact (required)")
	fs.Int64Var(&opts.version, "version", 0, "monotonic dataset version (required; the pipeline uses the run number)")
	fs.StringVar(&opts.generated, "generated-at", "", "override generated_at_utc (RFC3339; default: now, for reproducible re-builds)")
	fs.StringVar(&opts.keyFile, "key-file", "", "Ed25519 signing seed file (0600; default: the GSEER_DATASET_SIGNING_KEY secret)")
	_ = fs.Parse(args)
	if opts.dbPath == "" || opts.outDir == "" || opts.version <= 0 {
		usage()
		os.Exit(2)
	}
	if err := runBuild(opts); err != nil {
		fatal("%v", err)
	}
}

// runBuild exports the staging DB into a validated dataset artifact.
func runBuild(opts *buildOptions) error {
	generatedAt, gerr := resolveGeneratedAt(opts.generated)
	if gerr != nil {
		return gerr
	}
	db, err := sql.Open("sqlite", opts.dbPath)
	if err != nil {
		return fmt.Errorf("cannot open the staging database: %w", err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query(exportQuery)
	if err != nil {
		return fmt.Errorf("cannot read the staging evidence: %w", err)
	}
	defer func() { _ = rows.Close() }()

	_, gzw, closer, oerr := openPayloadWriter(opts.outDir)
	if oerr != nil {
		return oerr
	}
	enc := json.NewEncoder(gzw)

	summary := &buildSummary{
		assets:    map[string]bool{},
		perSource: map[string]*dataset.ProvenanceSummary{},
	}
	if err := streamStagingEvidence(rows, enc, summary); err != nil {
		_ = closer()
		return err
	}
	if err := gzw.Close(); err != nil {
		_ = closer()
		return fmt.Errorf("cannot finish the gzip payload: %w", err)
	}
	if err := closer(); err != nil {
		return fmt.Errorf("cannot finish the payload file: %w", err)
	}
	if summary.total == 0 {
		return fmt.Errorf("the staging database has NO exportable evidence — the pipeline collected nothing; refusing to publish an empty dataset")
	}
	return writeArtifact(opts, summary, generatedAt, loadSigningKeyOrWarn(opts.keyFile))
}

// resolveGeneratedAt resolves the manifest generation timestamp.
func resolveGeneratedAt(override string) (time.Time, error) {
	if override == "" {
		return time.Now().UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, override)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot parse --generated-at: %w", err)
	}
	return t.UTC(), nil
}

// exportQuery streams the staging evidence.  EXCLUSIONS (validated away,
// never exported): fixture rows (labeled synthetic evaluation data —
// never real) and the central-dataset bookkeeping row (a previous
// import's provenance marker, not collected evidence).
const exportQuery = `
SELECT o.id, o.observed_at, o.payload_hash, o.provenance, o.evidence,
       ds.name AS source_name, ds.connector AS source_connector,
       a.kind, a.value, a.ip, a.domain, a.hostname,
       a.asn, a.asn_org, a.geo_country, a.geo_region, a.geo_city, a.sources,
       s.port, s.transport, s.protocol, s.name AS svc_name, s.product, s.version
FROM observations o
JOIN assets a       ON a.id  = o.asset_id
JOIN data_sources ds ON ds.id = o.source_id
LEFT JOIN services s ON s.id  = o.service_id
WHERE ds.connector != 'fixture'
  AND o.provenance  != 'fixture'
  AND ds.name       != 'central-dataset'
ORDER BY o.id`

// openPayloadWriter opens the payload file + gzip writer; closer closes
// both (call after gzw.Close for the final flush).
func openPayloadWriter(outDir string) (*os.File, *gzip.Writer, func() error, error) {
	if err := os.MkdirAll(outDir, 0o750); err != nil { // #nosec G301 -- maintainer tool; artifact dir is operator-local
		return nil, nil, nil, fmt.Errorf("cannot create the output directory: %w", err)
	}
	payloadPath := filepath.Join(outDir, dataset.PayloadFilename)
	// #nosec G304 -- payloadPath is the operator-provided -out directory
	// joined with the PINNED constant dataset.PayloadFilename.
	payloadFile, err := os.OpenFile(payloadPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // local artifact copy; the publish step sets the release asset permissions
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create the payload file: %w", err)
	}
	gzw := gzip.NewWriter(payloadFile)
	return payloadFile, gzw, payloadFile.Close, nil
}

// streamStagingEvidence validates + encodes every staging row and folds
// it into the summary.  ONE invalid record fails the whole build.
func streamStagingEvidence(rows *sql.Rows, enc *json.Encoder, summary *buildSummary) error {
	for rows.Next() {
		row, serr := scanStagingRow(rows)
		if serr != nil {
			return fmt.Errorf("cannot read a staging evidence row: %w", serr)
		}
		rec, verr := buildRecord(row)
		if verr != nil {
			return fmt.Errorf("validation FAILED for staging observation %d — the dataset is refused: %w", row.id, verr)
		}
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("cannot encode record %d: %w", row.id, err)
		}
		accumulateBuildSummary(summary, rec)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("staging evidence scan failed: %w", err)
	}
	return nil
}

// accumulateBuildSummary folds one validated record into the summary
// (counts, freshness window, per-source provenance).
func accumulateBuildSummary(s *buildSummary, rec *dataset.Record) {
	s.total++
	s.assets[rec.Asset.Kind+"|"+rec.Asset.Value] = true
	if rec.Service != nil {
		s.services++
	}
	at := rec.Observation.ObservedAt
	if s.oldest.IsZero() || at.Before(s.oldest) {
		s.oldest = at
	}
	if s.newest.IsZero() || at.After(s.newest) {
		s.newest = at
	}
	p := s.perSource[rec.Observation.Source]
	if p == nil {
		p = &dataset.ProvenanceSummary{Source: rec.Observation.Source, Connector: rec.Observation.Connector}
		s.perSource[rec.Observation.Source] = p
	}
	p.Records++
	if at.After(p.NewestObservedAt) {
		p.NewestObservedAt = at
	}
}

// writeArtifact assembles, validates, signs (when a signing key is
// available), and writes the manifest next to the finished payload.
// Without a signing key the manifest is written UNSIGNED with a loud
// warning — the validate/publish gate refuses unsigned artifacts.
func writeArtifact(opts *buildOptions, summary *buildSummary, generatedAt time.Time, signKey ed25519.PrivateKey) error {
	payloadPath := filepath.Join(opts.outDir, dataset.PayloadFilename)
	st, err := os.Stat(payloadPath)
	if err != nil {
		return fmt.Errorf("cannot stat the payload: %w", err)
	}
	raw, err := os.ReadFile(payloadPath) // #nosec G304 -- the artifact we just wrote (pinned constant filename)
	if err != nil {
		return fmt.Errorf("cannot re-read the payload for checksumming: %w", err)
	}
	sum := sha256.Sum256(raw)

	manifest := &dataset.Manifest{
		SchemaVersion:  dataset.SchemaVersion,
		DatasetVersion: opts.version,
		GeneratedAtUTC: generatedAt,
		Payload: dataset.PayloadInfo{
			Filename:  dataset.PayloadFilename,
			SHA256:    hex.EncodeToString(sum[:]),
			SizeBytes: st.Size(),
			Records:   summary.total,
		},
		Rows: dataset.RowsInfo{
			Assets:       int64(len(summary.assets)),
			Services:     summary.services,
			Observations: summary.total,
		},
		Freshness: dataset.FreshnessInfo{
			OldestObservedAt: summary.oldest.UTC(),
			NewestObservedAt: summary.newest.UTC(),
		},
		ValidatorVersion: "1",
		Notes: "coverage: the seed register (pipeline/dataset-seeds.yaml) plus the seed-free " +
			"CT-log window (docs/SOURCES.md §G) — real passive discovery evidence over the " +
			"terms-reviewed connectors; NOT internet-wide coverage.",
	}
	for _, p := range summary.perSource {
		manifest.Provenance = append(manifest.Provenance, *p)
	}
	sortProvenance(manifest.Provenance)
	// The publisher-side shape gate (no signature requirement yet —
	// signing happens right after, when a key is available).
	if err := manifest.ValidateCore(); err != nil {
		return fmt.Errorf("the generated manifest failed validation: %w", err)
	}
	var manifestRaw []byte
	if signKey != nil {
		// P0-1: sign the canonical core — the signature binds the
		// manifest (version, checksums, provenance, freshness) and the
		// payload identity in one unambiguous block.
		manifestRaw, err = dataset.SignManifest(manifest, signKey)
		if err != nil {
			return fmt.Errorf("cannot sign the manifest: %w", err)
		}
	} else {
		manifestRaw, err = json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return fmt.Errorf("cannot encode the manifest: %w", err)
		}
		manifestRaw = append(manifestRaw, '\n')
	}
	manifestPath := filepath.Join(opts.outDir, dataset.ManifestFilename)
	// #nosec G304 -- manifestPath is the operator-provided -out directory
	// joined with the PINNED constant dataset.ManifestFilename.
	if err := os.WriteFile(manifestPath, append(manifestRaw, '\n'), 0o600); err != nil { // local artifact copy; the publish step sets the release asset permissions
		return fmt.Errorf("cannot write the manifest: %w", err)
	}

	fmt.Printf("[ ok ] dataset v%d built: %d records, %d assets, %d service-bearing records\n",
		opts.version, summary.total, len(summary.assets), summary.services)
	fmt.Printf("[ ok ] freshness: observed %s .. %s (UTC)\n",
		summary.oldest.UTC().Format(time.RFC3339), summary.newest.UTC().Format(time.RFC3339))
	fmt.Printf("[ ok ] payload: %s sha256=%s (%d bytes)\n", dataset.PayloadFilename, manifest.Payload.SHA256, st.Size())
	fmt.Printf("[ ok ] manifest: %s\n", manifestPath)
	if signKey != nil {
		fmt.Printf("[ ok ] signed with key %s (signature binds the manifest core + payload sha256/size/records)\n",
			dataset.KeyID(signKey.Public().(ed25519.PublicKey)))
		fmt.Printf("Next: gseer-dataset validate -dir %s   (the pipeline refuses to publish without a passing validate)\n", opts.outDir)
	} else {
		fmt.Printf("[WARN] manifest is UNSIGNED — no signing key was provided (-key-file / GSEER_DATASET_SIGNING_KEY).\n")
		fmt.Printf("       An unsigned dataset CANNOT pass validate and consumers refuse it: gseer-dataset sign -dir %s -key-file <seed>\n", opts.outDir)
	}
	return nil
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

// loadSigningKeyOrWarn resolves the signing key (file > env), returning
// nil WITHOUT an error when none is configured — the caller prints the
// unsigned warning.  Key material NEVER reaches errors or stdout.
func loadSigningKeyOrWarn(keyFile string) ed25519.PrivateKey {
	key, err := loadSigningKey(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gseer-dataset: signing key unavailable (%v) — building UNSIGNED\n", err)
		return nil
	}
	return key
}

// loadSigningKey resolves the Ed25519 private seed: -key-file (0600
// enforced) or the GSEER_DATASET_SIGNING_KEY secret (base64 or hex, 32
// bytes).  The seed is consumed in memory only.
func loadSigningKey(keyFile string) (ed25519.PrivateKey, error) {
	var raw []byte
	if keyFile != "" {
		st, err := os.Stat(keyFile)
		if err != nil {
			return nil, fmt.Errorf("cannot stat -key-file: %w", err)
		}
		if st.Mode().Perm() != 0o600 {
			return nil, fmt.Errorf("signing seed file %s has mode %04o — a private seed must be 0600; chmod 600 it and retry", keyFile, uint32(st.Mode().Perm()))
		}
		b, err := os.ReadFile(keyFile) // #nosec G304 -- the operator-provided seed path (a maintainer secret file)
		if err != nil {
			return nil, fmt.Errorf("cannot read the seed file: %w", err)
		}
		raw = b
	} else if env := os.Getenv("GSEER_DATASET_SIGNING_KEY"); env != "" {
		raw = []byte(env)
	} else {
		return nil, nil // nothing configured — build unsigned, honestly
	}
	seed, err := decodeSeed(raw)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// decodeSeed parses a 32-byte seed in base64-std or hex form.
func decodeSeed(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, fmt.Errorf("the signing seed is empty")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.SeedSize {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.SeedSize {
		return b, nil
	}
	return nil, fmt.Errorf("the signing seed is not a 32-byte base64/hex value")
}

// signCmd signs an existing artifact directory's manifest.
func signCmd(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	dir := fs.String("dir", "", "artifact directory containing the manifest (required)")
	keyFile := fs.String("key-file", "", "Ed25519 signing seed file (0600; default: the GSEER_DATASET_SIGNING_KEY secret)")
	_ = fs.Parse(args)
	if *dir == "" {
		usage()
		os.Exit(2)
	}
	key, err := loadSigningKey(*keyFile)
	if err != nil {
		fatal("sign FAILED: %v", err)
	}
	if key == nil {
		fatal("sign FAILED: no signing key (-key-file or the GSEER_DATASET_SIGNING_KEY secret)")
	}
	manifestPath := filepath.Join(*dir, dataset.ManifestFilename)
	raw, err := os.ReadFile(manifestPath) // #nosec G304 -- pinned constant filename in the operator's artifact directory
	if err != nil {
		fatal("sign FAILED: manifest missing: %v", err)
	}
	m, err := dataset.ParseManifestUnsigned(raw)
	if err != nil {
		fatal("sign FAILED: %v", err)
	}
	signed, err := dataset.SignManifest(m, key)
	if err != nil {
		fatal("sign FAILED: %v", err)
	}
	// Re-parse through the STRICT gate: what the consumer sees must be
	// exactly what this command accepts.
	if _, err := dataset.ParseManifest(signed); err != nil {
		fatal("sign FAILED: the signed manifest does not re-validate: %v", err)
	}
	if err := os.WriteFile(manifestPath, signed, 0o600); err != nil {
		fatal("sign FAILED: cannot write the signed manifest: %v", err)
	}
	fmt.Printf("[ ok ] manifest signed with key %s\n", dataset.KeyID(key.Public().(ed25519.PublicKey)))
	fmt.Printf("Next: gseer-dataset validate -dir %s\n", *dir)
}

// keygenCmd generates a fresh signing keypair: the private seed to the
// -out file (0600, refused on overwrite), the public half + key ID to
// stdout (for embedding into internal/dataset/keys.go).  The seed is
// never printed.
func keygenCmd(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "seed file to create (required; 0600)")
	_ = fs.Parse(args)
	if *out == "" {
		usage()
		os.Exit(2)
	}
	if _, err := os.Stat(*out); err == nil {
		fatal("keygen FAILED: %s already exists — refusing to overwrite a signing key", *out)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		fatal("keygen FAILED: cannot generate the seed: %v", err)
	}
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		fatal("keygen FAILED: cannot write the seed file: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("[ ok ] signing keypair generated: %s (0600; keep it in the CI secret store — NEVER in the repository)\n", *out)
	fmt.Printf("  public key (base64): %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("  key id             : %s\n", dataset.KeyID(pub))
	fmt.Printf("Next: embed public key + key id into internal/dataset/keys.go (docs/DATASET.md §5); publish the seed to the pipeline secret GSEER_DATASET_SIGNING_KEY.\n")
}

// sortProvenance orders the provenance summary deterministically.
func sortProvenance(list []dataset.ProvenanceSummary) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].Source < list[j-1].Source; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

func validateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	dir := fs.String("dir", "", "artifact directory containing the manifest + payload (required)")
	_ = fs.Parse(args)
	if *dir == "" {
		usage()
		os.Exit(2)
	}
	if err := runValidate(*dir); err != nil {
		fatal("validate FAILED: %v", err)
	}
	fmt.Println("[ ok ] dataset artifact validates (manifest schema, SIGNATURE against the trusted keyring, payload checksum, record count, per-record validation)")
}

// runValidate re-verifies a built artifact end-to-end.  The signature
// gate is fail-closed: ParseManifest refuses a missing/malformed
// signature block, and VerifyTrusted refuses a signature the trusted
// keyring cannot verify — an unsigned artifact cannot pass.
func runValidate(dir string) error {
	// #nosec G304 -- dir is the operator-provided artifact directory; the
	// joined filename is the PINNED constant dataset.ManifestFilename.
	manifestRaw, err := os.ReadFile(filepath.Join(dir, dataset.ManifestFilename))
	if err != nil {
		return fmt.Errorf("manifest missing: %w", err)
	}
	m, err := dataset.ParseManifest(manifestRaw)
	if err != nil {
		return err
	}
	if err := dataset.VerifyTrusted(m); err != nil {
		return err
	}
	payloadPath := filepath.Join(dir, m.Payload.Filename)
	// The payload filename is PINNED by Manifest.Validate (anything but
	// the constant PayloadFilename is refused), so the joined path cannot
	// traverse outside the artifact directory.
	f, err := os.Open(payloadPath) // #nosec G304,G703 -- pinned constant filename in the operator's artifact directory
	if err != nil {
		return fmt.Errorf("payload missing: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return fmt.Errorf("payload hash failed: %w", err)
	}
	if size != m.Payload.SizeBytes {
		return fmt.Errorf("payload size mismatch: manifest %d, file %d", m.Payload.SizeBytes, size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.Payload.SHA256 {
		return fmt.Errorf("payload checksum mismatch: manifest %s, file %s", m.Payload.SHA256, got)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("payload is not valid gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	dec := json.NewDecoder(gz)
	dec.DisallowUnknownFields()
	var n int64
	for {
		var rec dataset.Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("record %d does not parse: %w", n+1, err)
		}
		n++
		if err := validateRecordForBuild(&rec); err != nil {
			return fmt.Errorf("record %d failed validation: %w", n, err)
		}
	}
	if n != m.Payload.Records {
		return fmt.Errorf("record count mismatch: manifest %d, payload %d", m.Payload.Records, n)
	}
	return nil
}

// buildRecord converts one staging row into a validated dataset record.
func buildRecord(row *stagingRow) (*dataset.Record, error) {
	observedAt, err := parseObservedAt(row.observedAtRaw)
	if err != nil {
		return nil, err
	}
	if row.payloadHash == "" {
		return nil, fmt.Errorf("payload_hash is empty")
	}
	if row.sourceName == "" || row.sourceConnector == "" {
		return nil, fmt.Errorf("source name/connector is empty")
	}
	evidence, err := parseEvidence(row.evidenceRaw)
	if err != nil {
		return nil, err
	}
	sources, err := parseSources(row.sources)
	if err != nil {
		return nil, err
	}

	rec := &dataset.Record{
		Schema: dataset.SchemaVersion,
		Asset:  buildAsset(row, sources),
		Observation: dataset.RecordObservation{
			Source:      row.sourceName,
			Connector:   row.sourceConnector,
			ObservedAt:  observedAt.UTC(),
			PayloadHash: row.payloadHash,
			Provenance:  row.provenance,
			Evidence:    evidence,
		},
	}
	rec.Service = buildService(row)
	// Validate with the SAME rules the importer enforces (one contract).
	if err := validateRecordForBuild(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

func parseObservedAt(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err == nil {
		return t, nil
	}
	t, err = time.Parse("2006-01-02 15:04:05.999999999-07:00", raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("observed_at %q does not parse", raw)
	}
	return t, nil
}

func parseEvidence(raw string) (map[string]any, error) {
	var evidence map[string]any
	if err := json.Unmarshal([]byte(raw), &evidence); err != nil {
		return nil, fmt.Errorf("evidence JSON does not parse: %w", err)
	}
	return evidence, nil
}

func parseSources(raw string) ([]string, error) {
	if raw == "" || raw == "[]" {
		return nil, nil
	}
	var sources []string
	if err := json.Unmarshal([]byte(raw), &sources); err != nil {
		return nil, fmt.Errorf("asset sources JSON does not parse: %w", err)
	}
	return sources, nil
}

// buildAsset maps the staging row's asset columns into the record asset.
func buildAsset(row *stagingRow, sources []string) dataset.RecordAsset {
	a := dataset.RecordAsset{Kind: row.kind, Value: row.value, Sources: sources}
	setIf := func(dst **string, v sql.NullString) {
		if v.Valid && v.String != "" {
			s := v.String
			*dst = &s
		}
	}
	setIf(&a.IP, row.ip)
	setIf(&a.Domain, row.domain)
	setIf(&a.Hostname, row.host)
	if row.asn.Valid {
		a.ASN = int(row.asn.Int64)
	}
	setStr := func(dst *string, v sql.NullString) {
		if v.Valid && v.String != "" {
			*dst = v.String
		}
	}
	setStr(&a.ASNOrg, row.asnOrg)
	setStr(&a.GeoCountry, row.geoCountry)
	setStr(&a.GeoRegion, row.geoRegion)
	setStr(&a.GeoCity, row.geoCity)
	return a
}

// buildService maps the staging row's optional service columns.
func buildService(row *stagingRow) *dataset.RecordService {
	if !row.svcPort.Valid {
		return nil
	}
	s := &dataset.RecordService{
		Port:      int(row.svcPort.Int64),
		Transport: row.svcTransport.String,
		Protocol:  row.svcProtocol.String,
	}
	setStr := func(dst *string, v sql.NullString) {
		if v.Valid {
			*dst = v.String
		}
	}
	setStr(&s.Name, row.svcName)
	setStr(&s.Product, row.svcProduct)
	setStr(&s.Version, row.svcVersion)
	return s
}

// validateRecordForBuild applies the SAME rules the importer enforces
// (one contract — docs/DATASET.md §2).
func validateRecordForBuild(rec *dataset.Record) error {
	if rec.Schema != dataset.SchemaVersion {
		return fmt.Errorf("schema %d is not %d", rec.Schema, dataset.SchemaVersion)
	}
	if rec.Asset.Value == "" {
		return fmt.Errorf("asset value is empty")
	}
	switch rec.Asset.Kind {
	case "ip", "domain", "hostname":
	default:
		return fmt.Errorf("asset kind %q is not a known kind", rec.Asset.Kind)
	}
	if rec.Observation.Source == "" || rec.Observation.Connector == "" {
		return fmt.Errorf("observation source/connector is empty")
	}
	if rec.Observation.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at is missing")
	}
	if rec.Observation.ObservedAt.After(time.Now().Add(dataset.MaxFutureSkew)) {
		return fmt.Errorf("observed_at is more than %s in the future", dataset.MaxFutureSkew)
	}
	if rec.Observation.PayloadHash == "" {
		return fmt.Errorf("payload_hash is missing")
	}
	if rec.Observation.Provenance == "" {
		return fmt.Errorf("provenance is missing")
	}
	if rec.Service != nil {
		if rec.Service.Port < 1 || rec.Service.Port > 65535 {
			return fmt.Errorf("service port %d is out of range", rec.Service.Port)
		}
		switch rec.Service.Transport {
		case "tcp", "udp":
		default:
			return fmt.Errorf("service transport %q is not tcp|udp", rec.Service.Transport)
		}
		if strings.TrimSpace(rec.Service.Protocol) == "" {
			return fmt.Errorf("service protocol is empty")
		}
	}
	return nil
}
