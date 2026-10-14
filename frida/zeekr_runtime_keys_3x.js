// zeekr_runtime_keys_3x.js
//
// Dump prod_secret + vin_key + vin_iv from com.zeekr.overseas v3.0.6 (EU 7X) at
// runtime. This build stores all three behind iWall ECIES. Older EU builds may
// differ; the class/method names below are confirmed only for v3.0.6.
//
// Prereqs: a rooted device/emulator, matching Frida client/server versions,
// and the app running and logged in. With Frida 17, use frida-tools >= 14,
// which supplies the Java bridge for CLI scripts. Sign in and refresh the
// vehicle page before attaching so the security SDK has initialised.
//
//   frida -U -n ZEEKR -l frida/zeekr_runtime_keys_3x.js
//   (the process shows up to frida as "ZEEKR", not the package name)
//
// If a newer build moves the getter class, configure encryptedBlobs below
// using the base64 constants from your own APK (xn/a.java on v3.0.6).
// The fallback still requires the yn.a decryptor and EnvType names to match.

(function () {
  if (typeof Java === 'undefined') {
    console.log('Java bridge unavailable. Use the frida CLI with frida-tools >= 14 for Frida 17, or bundle frida-java-bridge in a custom agent.');
    return;
  }

  Java.perform(function () {
    // Optional manual fallback. Leave unset to use the getters only.
    var encryptedBlobs = {
      prod_secret: null, // xn.a.c base64 from your APK
      vin_key: null,     // xn.a.a base64 from your APK
      vin_iv: null,      // xn.a.l base64 from your APK
    };
    var getters = { prod_secret: 'k', vin_key: 'j', vin_iv: 'c' };
    var names = Object.keys(getters);
    var out = {};
    var sources = {};
    var errors = [];

    function accept(name, value, method) {
      if (value === null || value === undefined) return;
      var text = String(value);
      var valid = name === 'prod_secret'
        ? /^[0-9a-fA-F]{32}$/.test(text)
        : /^[\x20-\x7e]{16}$/.test(text) && !/[<>]/.test(text);
      if (valid) { out[name] = text; sources[name] = method; }
    }

    // Read each getter independently so one failure cannot hide other values.
    try {
      var M = Java.use('com.zeekr.snc.log.m');
      var inst = M.a.value;
      if (inst === null || inst === undefined) {
        errors.push('Getter singleton is not initialised.');
      } else {
        names.forEach(function (name) {
          try { accept(name, inst[getters[name]](), 'getters'); }
          catch (e) { errors.push(name + ' getter: ' + e); }
        });
      }
    } catch (e) { errors.push('getter error: ' + e); }

    // Decrypt only missing values with configured, syntactically valid base64.
    var pending = names.filter(function (name) {
      var blob = encryptedBlobs[name];
      return !out[name] && typeof blob === 'string' && blob.length >= 4
        && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(blob);
    });
    if (pending.length) {
      try {
        var YA = Java.use('yn.a').$new();
        var P = Java.use('com.geely.snc.security.api.model.EnvType').PRODUCT.value;
        pending.forEach(function (name) {
          try { accept(name, YA.c(P, encryptedBlobs[name]), 'blobs'); }
          catch (e) { errors.push(name + ' blob decrypt: ' + e); }
        });
      } catch (e) { errors.push('blob error: ' + e); }
    }

    console.log('--- Zeekr runtime secrets (com.zeekr.overseas v3.0.6) ---');
    names.forEach(function (name) {
      console.log(name + ': ' + (out[name] || 'NOT FOUND'));
    });
    var missing = names.filter(function (name) { return !out[name]; });
    if (missing.length) {
      console.log('Missing runtime values: ' + missing.join(', '));
      console.log('Log in, refresh the vehicle page, then re-run. Class names may differ on other builds.');
      console.log('For manual fallback, fill encryptedBlobs with the constants from your APK and verify the decryptor class names.');
      errors.forEach(function (error) { console.log(error); });
    } else {
      console.log('All three runtime values extracted (format checked; API validity must be tested separately).');
    }
    console.log('method: ' + names.filter(function (name) { return out[name]; })
      .map(function (name) { return name + '=' + sources[name]; }).join(', '));
    console.log('Do not publish these values — they are app-global constants; everyone extracts their own.');
  });
})();
