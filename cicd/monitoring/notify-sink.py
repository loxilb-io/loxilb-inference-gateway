#!/usr/bin/env python3
"""Local Alertmanager webhook sink for notification-path validation.

Receives Alertmanager webhook posts on :9095 and appends one JSON line per
notification to the --out file: {ts, status, alertname, fingerprint}. The
canary driver tails that file to prove fire -> delivery -> resolve, and the
redaction check greps it for secrets. Stdlib only.
"""
import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9095)
    ap.add_argument("--out", default="notify-sink.jsonl")
    args = ap.parse_args()

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            try:
                msg = json.loads(body)
            except json.JSONDecodeError:
                self.send_response(400); self.end_headers(); return
            with open(args.out, "a") as fh:
                for a in msg.get("alerts", []):
                    fh.write(json.dumps({
                        "ts": time.time(),
                        "status": a.get("status"),
                        "alertname": a.get("labels", {}).get("alertname"),
                        "fingerprint": a.get("fingerprint"),
                    }) + "\n")
            self.send_response(200); self.end_headers()

        def log_message(self, *a):
            pass

    HTTPServer(("127.0.0.1", args.port), H).serve_forever()

if __name__ == "__main__":
    main()
