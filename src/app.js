const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// ─── FLAGS ────────────────────────────────────────────────────────────────────
const FLAGS = {
  1:  'FLAG{x_forwarded_4_bypass}',
  2:  'FLAG{x_rewrite_url_trick}',
  3:  'FLAG{path_traversal_bypass}',
  4:  'FLAG{method_override_win}',
  5:  'FLAG{x_original_url_bypass}',
  6:  'FLAG{case_sensitivity_bypass}',
  7:  'FLAG{double_slash_bypass}',
  8:  'FLAG{content_type_confusion}',
};

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function respond403(res, hint) {
  res.status(403).json({ status: 403, error: 'Forbidden', hint });
}

function respondFlag(res, challengeNum) {
  res.json({ status: 200, message: 'Access granted!', flag: FLAGS[challengeNum] });
}

// ─── CHALLENGE 1: X-Forwarded-For bypass ─────────────────────────────────────
// Hint: Admin panel only accessible from internal IP 127.0.0.1
app.get('/challenge/1/admin', (req, res) => {
  const xff = req.headers['x-forwarded-for'];
  const forwardedIPs = xff ? xff.split(',').map(s => s.trim()) : [];
  const clientIP = forwardedIPs[0] || req.socket.remoteAddress;

  if (clientIP === '127.0.0.1' || clientIP === '::1' || clientIP === 'localhost') {
    respondFlag(res, 1);
  } else {
    respond403(res, 'Admin panel is restricted to internal network (127.0.0.1)');
  }
});

// ─── CHALLENGE 2: X-Rewrite-URL bypass ───────────────────────────────────────
// The WAF blocks /secret directly. Can you trick the server?
app.get('/challenge/2/public', (req, res) => {
  const rewriteUrl = req.headers['x-rewrite-url'];
  if (rewriteUrl && rewriteUrl.includes('/secret')) {
    respondFlag(res, 2);
  } else {
    res.json({ status: 200, message: 'Public endpoint - nothing here.' });
  }
});

app.get('/challenge/2/secret', (req, res) => {
  respond403(res, 'This path is blocked by the WAF. Maybe you can reach it another way?');
});

// ─── CHALLENGE 3: Path traversal / URL encoding bypass ───────────────────────
// /challenge/3/private is blocked. Try encoding or traversal.
app.get('/challenge/3/private', (req, res) => {
  respond403(res, 'Access denied. Hint: the check is done on the raw path, not decoded path.');
});

// Middleware catches encoded variants BEFORE the route above fires in some configs
// We manually handle decoded traversal paths
app.use((req, res, next) => {
  const raw = req.url;
  // Match encoded versions of /challenge/3/private
  const decodedAttempts = [
    '/challenge/3/%70rivate',
    '/challenge/3/..%2F..%2Fchallenge%2F3%2Fprivate',
    '/challenge/3/./private',
    '/challenge/3/%2e/private',
  ];
  const decoded = decodeURIComponent(raw);
  if (
    decodedAttempts.includes(raw) ||
    decoded === '/challenge/3/./private' ||
    raw === '/challenge/3/%2e/private' ||
    raw === '/challenge/3/%70rivate' ||
    raw.includes('/challenge/3/') && raw.includes('%')
  ) {
    if (raw !== '/challenge/3/private') {
      res.json({ status: 200, message: 'Path normalization bypass detected!', flag: FLAGS[3] });
      return;
    }
  }
  next();
});

// ─── CHALLENGE 4: HTTP Method Override bypass ─────────────────────────────────
// GET is blocked. POST is blocked. Find a way to "override" the method.
app.all('/challenge/4/resource', (req, res) => {
  const override =
    req.headers['x-http-method-override'] ||
    req.headers['x-method-override'] ||
    req.headers['x-custom-method'] ||
    req.query._method;

  const effectiveMethod = override ? override.toUpperCase() : req.method;

  if (['GET', 'POST'].includes(req.method) && !override) {
    respond403(res, 'GET and POST are blocked. Try overriding the HTTP method with a header.');
  } else if (effectiveMethod === 'PATCH' || effectiveMethod === 'PUT') {
    respondFlag(res, 4);
  } else {
    respond403(res, 'Interesting... but not quite. Hint: PATCH or PUT override.');
  }
});

// ─── CHALLENGE 5: X-Original-URL bypass ──────────────────────────────────────
// /challenge/5/internal is blocked at the "proxy" layer.
app.get('/challenge/5/gateway', (req, res) => {
  const originalUrl = req.headers['x-original-url'];
  if (originalUrl && originalUrl.includes('/internal')) {
    respondFlag(res, 5);
  } else {
    res.json({ status: 200, message: 'Gateway endpoint. The internal API is somewhere else.' });
  }
});

app.get('/challenge/5/internal', (req, res) => {
  respond403(res, 'Internal API - not accessible directly. Hint: some frameworks honor X-Original-URL.');
});

// ─── CHALLENGE 6: Case sensitivity bypass ────────────────────────────────────
app.use((req, res, next) => {
  if (!req.url.startsWith('/challenge/6/')) return next();

  const raw = req.url.split('?')[0];

  if (raw === '/challenge/6/admin') {
    return respond403(res, 'Admin route is blocked. What if the ACL check is case-sensitive?');
  }

  if (raw.toLowerCase() === '/challenge/6/admin') {
    return respondFlag(res, 6);
  }

  next();
});

// ─── CHALLENGE 7: Double slash / extra slash bypass ──────────────────────────
// The WAF pattern matches exactly ^/challenge/7/hidden$
app.use((req, res, next) => {
  const url = req.url;
  if (
    url === '//challenge/7/hidden' ||
    url === '/challenge/7//hidden' ||
    url === '/challenge//7/hidden' ||
    url.startsWith('/challenge/7/hidden/') ||
    url.includes('/challenge/7/./hidden') ||
    url.match(/\/challenge\/7\/[.\/]+hidden/)
  ) {
    res.json({ status: 200, message: 'Slash normalization bypass!', flag: FLAGS[7] });
    return;
  }
  next();
});

app.get('/challenge/7/hidden', (req, res) => {
  respond403(res, 'Path is blocked. The WAF matches exact paths — what if you add an extra slash or dot?');
});

// ─── CHALLENGE 8: Content-Type confusion bypass ───────────────────────────────
// The endpoint checks Content-Type to gate access to the admin action.
app.post('/challenge/8/action', (req, res) => {
  const ct = req.headers['content-type'] || '';

  // Firewall blocks application/json and application/x-www-form-urlencoded
  if (ct.includes('application/json') || ct.includes('application/x-www-form-urlencoded')) {
    respond403(res, 'That Content-Type is blocked. Try an unexpected one. Hint: application/xml, text/plain, or something weird.');
    return;
  }

  // Any other content type gets through
  respondFlag(res, 8);
});

// ─── SCOREBOARD API ───────────────────────────────────────────────────────────
app.get('/api/challenges', (req, res) => {
  res.json({
    challenges: [
      { id: 1, title: 'Internal Network Spoof',     category: 'Header Injection',    difficulty: 'Easy',   endpoint: 'GET /challenge/1/admin',    hint: 'Think about how reverse proxies forward client IPs.' },
      { id: 2, title: 'WAF URL Rewrite',            category: 'Header Injection',    difficulty: 'Easy',   endpoint: 'GET /challenge/2/public',   hint: 'Some servers let you rewrite the target URL via a header.' },
      { id: 3, title: 'Path Normalization',         category: 'URL Manipulation',    difficulty: 'Medium', endpoint: 'GET /challenge/3/private',  hint: 'URL encoding, dot segments, and percent-encoding are your friends.' },
      { id: 4, title: 'Method Override',            category: 'HTTP Method',         difficulty: 'Medium', endpoint: 'ANY /challenge/4/resource', hint: 'Frameworks support method overriding via special headers or query params.' },
      { id: 5, title: 'X-Original-URL Smuggling',  category: 'Header Injection',    difficulty: 'Medium', endpoint: 'GET /challenge/5/gateway',  hint: 'Some frameworks route based on X-Original-URL before the ACL sees it.' },
      { id: 6, title: 'ACL Case Sensitivity',       category: 'URL Manipulation',    difficulty: 'Easy',   endpoint: 'GET /challenge/6/admin',    hint: 'Uppercase? Lowercase? Mixed? ACLs can be picky.' },
      { id: 7, title: 'Slash Confusion',            category: 'URL Manipulation',    difficulty: 'Hard',   endpoint: 'GET /challenge/7/hidden',   hint: 'Extra slashes, path traversal dots — WAF regex vs server normalization.' },
      { id: 8, title: 'Content-Type Smuggling',     category: 'Protocol Abuse',      difficulty: 'Hard',   endpoint: 'POST /challenge/8/action',  hint: 'The firewall only knows about common Content-Types.' },
    ]
  });
});

app.get('/api/verify', (req, res) => {
  const { flag } = req.query;
  const valid = Object.values(FLAGS).includes(flag);
  const challengeId = valid ? Object.keys(FLAGS).find(k => FLAGS[k] === flag) : null;
  res.json({ valid, challengeId: challengeId ? parseInt(challengeId) : null });
});

// ─── SERVE SPA ────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`403 Bypass Lab running on :${PORT}`));
