#!/usr/bin/env python3
"""Mistral chat-completions adapter for scripts/evaluate_model.py.

Reads one JSON request object on stdin ({"messages": [...]}) and writes ONLY the
candidate policy text to stdout, per the external_model.py contract.

The API key is read from MISTRAL_API_KEY or, failing that, from a key file
(default ~/.mistral_key). The key is never echoed, logged, or written to any
artifact. Provider stderr is not forwarded, because it can carry credentials.

Output normalisation is deliberately minimal and is recorded in the run config:
a single surrounding Markdown code fence is stripped, because models routinely
fence JSON and grading fenced output would measure formatting rather than policy
quality. Nothing else about the response is altered.

HTTP 429 and 403 are retried up to MISTRAL_RETRIES times with linear backoff.
On this tier Mistral returns 403 for transient capacity as well as for genuine
lack of access -- the same model and prompt that returned 403 succeeded on
immediate retry -- so 403 is treated as retryable. If every retry still fails,
the caller records an execution error, never a graded INVALID verdict, so a
transport failure can never be mistaken for a model answer.
"""
import time
import argparse
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

API_URL = "https://api.mistral.ai/v1/chat/completions"


def read_key():
    key = os.environ.get("MISTRAL_API_KEY", "").strip()
    if key:
        return key
    path = pathlib.Path(os.environ.get("MISTRAL_KEY_FILE", "~/.mistral_key")).expanduser()
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    raise SystemExit("No Mistral API key: set MISTRAL_API_KEY or create ~/.mistral_key")


def strip_fence(text):
    lines = text.strip().splitlines()
    if len(lines) >= 2 and lines[0].lstrip().startswith("```") and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return text.strip()


def main():
    # Model and sampling are CLI arguments, not environment variables, so the
    # exact invocation is captured in the run metadata's "command" field and the
    # recorded model identifier cannot silently disagree with what was called.
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--temperature", type=float, default=0.0)
    args = ap.parse_args()
    request = json.load(sys.stdin)
    payload = {
        "model": args.model,
        "messages": request["messages"],
        "temperature": args.temperature,
    }
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {read_key()}", "Content-Type": "application/json"},
        method="POST",
    )
    time.sleep(float(os.environ.get("MISTRAL_REQUEST_DELAY", "2")))
    retries = int(os.environ.get("MISTRAL_RETRIES", "3"))
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=110) as resp:
                body = json.load(resp)
            break
        except urllib.error.HTTPError as exc:
            # Status only. Response bodies can echo request content or key fragments.
            if exc.code in (429, 403) and attempt < retries:
                time.sleep(5 * (attempt + 1))
                continue
            raise SystemExit(f"Mistral HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise SystemExit(f"Mistral transport error: {exc.reason}")
    sys.stdout.write(strip_fence(body["choices"][0]["message"]["content"]))


if __name__ == "__main__":
    main()
