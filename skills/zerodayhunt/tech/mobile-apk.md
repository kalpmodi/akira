# ZDH Phase 13: Mobile APK Analysis

## Phase 13 - Mobile APK Analysis

**Goal:** APKs contain hardcoded secrets and APIs that never appear in web.

```bash
# 1. Download APK (from Google Play or APKPure)
# 2. Decompile with jadx
jadx -d ./apk_output <app>.apk

# 3. Hunt for secrets in decompiled source
grep -r "apiKey\|secretKey\|password\|token\|Bearer\|Authorization" ./apk_output/sources/
grep -r "http[s]://" ./apk_output/sources/ | grep -v "schema\|dtd\|android" | head -50

# 4. Check strings in resources
grep -r "key\|secret\|token" ./apk_output/resources/ | grep -v "\.png\|\.xml:" | head -50

# 5. Extract from native libraries
strings ./apk_output/lib/arm64-v8a/*.so | grep -E "Bearer|api[_-]?key|secret"

# 6. Check AndroidManifest.xml
cat ./apk_output/resources/AndroidManifest.xml
# Look for: exported activities, permissions, custom URL schemes, intent filters

# 7. Find hardcoded IPs / internal endpoints
grep -r "192\.168\.\|10\.\|172\.\|\.internal\|\.corp\|\.local" ./apk_output/sources/

# 8. Certificate pinning check
grep -r "CertificatePinner\|TrustManager\|X509\|pinning" ./apk_output/sources/
# If found: bypass with Frida or apk-mitm tool

# 9. Frida hook for runtime secret extraction (on rooted device / emulator)
frida -U -n <app-package> -e "
Java.perform(function() {
  var OkHttpClient = Java.use('okhttp3.OkHttpClient\$Builder');
  OkHttpClient.build.implementation = function() {
    var result = this.build();
    // Hook to intercept all HTTP requests including headers
    return result;
  };
});
"

# 10. Check for debug API endpoints in APK that don't exist on web
grep -r "/debug/\|/test/\|/internal/\|/admin/" ./apk_output/sources/
```

**Signal:** `emit_signal CRED_FOUND "APK hardcoded: <key-type> in <class>" "main/zerodayhunt" 0.92`
