// zeekr_runtime_keys_3x.js
//
// Dump prod_secret + vin_key + vin_iv from com.zeekr.overseas v3.0.x (EU 7X) at
// runtime. On app >= 3.0 the prod_secret ALSO moved behind iWall ECIES (like the
// VIN key/iv on >= 1.5.7), so the static DEX prod_secret candidates no longer
// work — everything has to be dumped live.
//
// Prereqs: frida-server 16.x on the device (NOT 17 — it removed the Java bridge),
// the app installed and *** LOGGED IN once *** (the iWall SDK only initialises on
// the first signed request; before that the values aren't in memory).
//
//   frida -U -n ZEEKR -l frida/zeekr_runtime_keys_3x.js
//   (the process shows up to frida as "ZEEKR", not the package name)
//
// Class/method names are for v3.0.6. If a newer build moves them, use the blob
// fallback (paste the base64 blobs from xn/a.java) or re-locate the signer.

Java.perform(function () {
  function real(v) { return v !== null && v !== undefined && ('' + v).length >= 8; }
  var out = { _method: null };

  // Method A: read the already-decrypted values straight from the getters.
  try {
    var M = Java.use('com.zeekr.snc.log.m');   // holds the decrypted signing/VIN secrets
    var inst = M.a.value;                       // static instance
    if (inst !== null) {
      out.prod_secret = '' + inst.k();          // X-SIGNATURE HMAC key (32 hex)
      out.vin_key     = '' + inst.j();          // X-VIN AES key (16 chars)
      out.vin_iv      = '' + inst.c();          // X-VIN AES iv  (16 chars)
      if (real(out.prod_secret)) out._method = 'getters';
    }
  } catch (e) { out._getterError = '' + e; }

  // Method B: decrypt the blobs yourself (fallback). base64 from xn/a.java.
  if (!real(out.prod_secret)) {
    try {
      var PROD = '<xn.a.c base64 from your apk>';   // prod_secret
      var VKEY = '<xn.a.a base64 from your apk>';   // vin_key
      var VIV  = '<xn.a.l base64 from your apk>';   // vin_iv
      var YA = Java.use('yn.a').$new();             // the iWall decryptor
      var P  = Java.use('com.geely.snc.security.api.model.EnvType').PRODUCT.value;
      out.prod_secret = '' + YA.c(P, PROD);
      out.vin_key     = '' + YA.c(P, VKEY);
      out.vin_iv      = '' + YA.c(P, VIV);
      if (real(out.prod_secret)) out._method = 'blobs';
    } catch (e) { out._blobError = '' + e; }
  }

  console.log('--- Zeekr runtime secrets (com.zeekr.overseas v3.0.x) ---');
  console.log('prod_secret: ' + out.prod_secret);
  console.log('vin_key:     ' + out.vin_key);
  console.log('vin_iv:      ' + out.vin_iv);
  console.log('method:      ' + out._method);
  if (!real(out.prod_secret)) {
    console.log('');
    console.log('Empty/placeholder? Most likely you have not LOGGED IN yet — log in, then re-run.');
    console.log('If a newer build moved the classes, use the Method B blob fallback above.');
    if (out._getterError) console.log('getter error: ' + out._getterError);
  }
  console.log('');
  console.log('Do not publish these values — they are app-global constants; everyone extracts their own.');
});
