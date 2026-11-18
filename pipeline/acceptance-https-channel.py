#!/usr/bin/env python3
"""GSEER acceptance HTTPS channel (production-fidelity fixture).

Serves a dataset directory over REAL TLS with the GitHub Release download
path shape (/releases/download/central-dataset/<asset>).  This is the
LOCAL production-fidelity fixture used by pipeline/acceptance-journey.sh.

It is NOT the production channel and MUST NOT be presented as production
acceptance: production acceptance is consumption of the real GitHub
Release (see the journey's J10 step, which checks the official URL and
records the honest pending/live verdict).

Client-side certificate verification is enforced by Go's crypto/x509; the
test CA is injected via SSL_CERT_FILE.  Without the CA the handshake MUST
fail (x509: certificate signed by unknown authority) — that negative case
is part of the journey.

Usage: acceptance-https-channel.py ROOT PORT CERT KEY
"""
import http.server
import os
import ssl
import sys


class ReleaseHandler(http.server.SimpleHTTPRequestHandler):
    """Serves ROOT; /releases/download/central-dataset/<asset> resolves
    under ROOT/releases/download/central-dataset/."""

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main():
    if len(sys.argv) != 5:
        sys.exit("usage: acceptance-https-channel.py ROOT PORT CERT KEY")
    root, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    # Load the certificate chain BEFORE chdir so RELATIVE cert paths keep
    # working regardless of where the caller invoked this script.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    os.chdir(root)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), ReleaseHandler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("https channel up on 127.0.0.1:%d serving %s" % (port, root), flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
