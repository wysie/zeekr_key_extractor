# Zeekr Key Extractor

Extract the 6 secret values required by the [Zeekr Home Assistant integration](https://github.com/Fryyyyy/zeekr_homeassistant) and the [Zeekr EV API](https://github.com/Fryyyyy/zeekr_ev_api) library from the official Zeekr Android APK.

## Background

The Zeekr Home Assistant integration requires several secret values that are embedded in the Zeekr Android app. These values are used for API request signing, password encryption, and VIN encryption. Extracting them manually involves decompiling the APK with JADX and Ghidra, which can be a time-consuming process.

This tool automates the entire extraction process. It decompiles the DEX bytecode to find Java-level secrets and analyzes the native ARM64 libraries to recover the HMAC keys (OLLVM deobfuscation on app <= 1.5.5, plaintext table resolution on app >= 1.5.7).

> **Important for app >= 1.5.7:** Zeekr moved the VIN key/IV behind iWall ECIES encryption (`fi.a` / `SecuritySuiteSDK`, decrypted at runtime by `libiwallca.so`), so these two values can no longer be extracted statically. The extractor recovers the other 4 secrets (including the HMAC keys, which moved to a new plaintext table format in 1.6.0) and prints guidance for the VIN key/IV — see [VIN key/IV on app >= 1.5.7](#vin-keyiv-on-app--157). VIN key/IV extracted from a **v1.5.5 APK are still accepted by the Zeekr API**, so the simplest path is to run this tool on a 1.5.5 APK for those two values.

## Extracted Secrets

| Secret | Description | Source |
|---|---|---|
| HMAC Access Key | Used in `X-HMAC-ACCESS-KEY` header for API request signing | `libenv.so` (OLLVM <= 1.5.5, plaintext tables >= 1.5.7) |
| HMAC Secret Key | Used for HMAC-SHA256 signature computation | `libenv.so` (OLLVM <= 1.5.5, plaintext tables >= 1.5.7) |
| Password Public Key | RSA public key for encrypting the login password | DEX string table |
| Prod Secret | Used for `X-SIGNATURE` HMAC computation | DEX string table |
| VIN Key | AES-128-CBC key for encrypting the VIN in `X-VIN` header | DEX string table (app <= 1.5.5 only) |
| VIN IV | AES-128-CBC initialization vector for VIN encryption | DEX string table (app <= 1.5.5 only) |

## Requirements

- Python 3.10+
- An Android device (or emulator) with the Zeekr app installed
- ADB (Android Debug Bridge) for pulling the APK files

### Python Dependencies

```bash
pip install capstone pyelftools
```

## Usage

### Step 1: Pull the APK files from your device

Connect your Android device via USB (with USB debugging enabled) and run the appropriate command for your market:

> **Note on package names:** The Zeekr app uses different package names depending on your market:
> - **Most markets** (Singapore, Australia, SEA, EM): `com.zeekr.global`
> - **EU market** (confirmed in Netherlands and other EU countries): `com.zeekr.overseas`

**For most markets:**
```bash
adb shell pm path com.zeekr.global
```

**For EU market:**
```bash
adb shell pm path com.zeekr.overseas
```

This will output something like:

```
package:/data/app/~~XXXX==/com.zeekr.global-YYYY==/base.apk
package:/data/app/~~XXXX==/com.zeekr.global-YYYY==/split_config.arm64_v8a.apk
package:/data/app/~~XXXX==/com.zeekr.global-YYYY==/split_config.xxhdpi.apk
```

Pull the two required files:

```bash
adb pull <path_to_base.apk> zeekr_base.apk
adb pull <path_to_arm64_v8a.apk> zeekr_arm64.apk
```

The `split_config.xxhdpi.apk` is not needed (it only contains density-specific resources).

> **Using app >= 1.5.7? Read this first.** In v1.5.7 Zeekr moved the VIN key/IV behind iWall ECIES white-box encryption, which means **no static tool can extract them from a newer APK** — the EC private key that decrypts them only exists inside `libiwallca.so` at runtime. The recommended workflow is therefore:
>
> 1. Pull the **current** APK from your device and run this tool on it → you get the HMAC keys, RSA public key, and prod secret (these must match the app version you actually run).
> 2. Download **v1.5.5** of `com.zeekr.global` from an APK mirror (e.g. APKPure) and run this tool on it → you get the VIN key/IV.
> 3. Merge the two `zeekr_secrets.json` outputs (take `vin_key` + `vin_iv` from the 1.5.5 result).
>
> This works because Zeekr only changed **how the app stores** the VIN key/IV — the values themselves were **not rotated server-side**, and the API still accepts VIN headers encrypted with the 1.5.5 key/IV (confirmed against the live API). This is the only secret pair that may be mixed across app versions; all others must come from the version you run.
>
> **Shortcut:** since v1.5.5 still stores *everything* in plaintext, you can technically run this tool on a 1.5.5 APK alone and get all 6 secrets in one go — and those values have been confirmed working against the live API. Just be aware that Zeekr rotates some secrets between app versions (`prod_secret` changed between 1.5.3 and 1.5.5, and the HMAC keys may change too), so if an all-1.5.5 set ever stops working, re-extract the version-sensitive secrets (HMAC keys, prod secret) from the current APK and keep only the VIN key/IV from 1.5.5.

### Step 2: Run the extractor

```bash
python zeekr_extract_secrets.py zeekr_base.apk zeekr_arm64.apk
```

The default region is **EM** (Emerging Markets), which covers most countries outside China and Europe (including Singapore, Australia, etc.). To specify a different region:

```bash
python zeekr_extract_secrets.py zeekr_base.apk zeekr_arm64.apk --region EU
```

Available regions:

| Region | Coverage |
|---|---|
| `CN` | China |
| `SEA` | Southeast Asia |
| `EU` | Europe |
| `EM` | Emerging Markets (default) |

> **Note:** The region flag only affects the HMAC Access Key and HMAC Secret Key. The other 4 secrets are the same across all regions. If you are unsure which region to use, try `EM` first — it works for most countries outside China and Europe. The HMAC keys must match the API gateway region, which may differ from the TSP region code used internally by the app.

### Step 3: Review the output

The script will print all 6 secrets and save them to a `zeekr_secrets.json` file in the same directory as the APK:

```
============================================================
  Zeekr APK Secret Extractor
  Target region: EM
============================================================
[1/4] Extracting DEX files from base APK...
      Found 15 DEX files
[2/4] Extracting native libraries...
      Found 24 native libraries
[3/4] Searching DEX files for secrets...
      [OK] Password Public Key (216 chars)
      [OK] Prod Secret: ********************************
      [OK] VIN Key: ****************
      [OK] VIN IV:  ****************
[4/4] Decrypting native library secrets (OLLVM deobfuscation)...
      [OK] HMAC Access Key: ********************************
      [OK] HMAC Secret Key: ****************************************

  All 6 secrets extracted successfully!
  Secrets saved to: zeekr_secrets.json
```

## Using the Secrets

### With the Home Assistant Integration

1. Install the [Zeekr integration](https://github.com/Fryyyyy/zeekr_homeassistant) via [HACS](https://hacs.xyz/).
2. Add the integration in Home Assistant (Settings > Devices & Services > Add Integration > Zeekr).
3. Enter your Zeekr account credentials and the 6 extracted secrets when prompted.

> **Tip:** Create a dedicated Zeekr account and share your car with it to avoid session conflicts with the phone app.

### With the Python API Library

```bash
pip install zeekr-ev-api
```

```python
from zeekr_ev_api.client import ZeekrClient

client = ZeekrClient(
    username="your_email",
    password="your_password",
    hmac_access_key="<from zeekr_secrets.json>",
    hmac_secret_key="<from zeekr_secrets.json>",
    password_public_key="<from zeekr_secrets.json>",
    prod_secret="<from zeekr_secrets.json>",
    vin_key="<from zeekr_secrets.json>",
    vin_iv="<from zeekr_secrets.json>",
)

client.login()
print("Login successful!")
print(client.get_vehicle_list())
```

## How It Works

The extractor uses these techniques to find the secrets:

1. **DEX string table scanning** — The base APK contains multiple DEX files (Dalvik bytecode). The script searches for specific byte patterns in the DEX string tables:
   - RSA public keys (base64-encoded, starting with `MIGfMA0GCSq`)
   - 32-character hex strings with ULEB128 length prefix (prod secret)
   - 16-character hex string pairs in DEX files containing `AES/CBC/PKCS5Padding` (VIN key and IV, app <= 1.5.5 only)

2. **HMAC keys from `libenv.so`** — two storage generations are supported:
   - **App <= 1.5.5 (OLLVM deobfuscation):** the keys are stored in `libenv.so` protected with [OLLVM](https://github.com/nickcano/OLLVM) string encryption. The script disassembles `.text` with [Capstone](https://www.capstone-engine.org/), finds the XOR decryption function by scanning for dense `EOR` regions, applies the XOR operations in-place, and maps the decrypted strings to regions via the ELF relocation table.
   - **App >= 1.5.7 (plaintext table resolution):** Zeekr dropped the OLLVM layer; `libenv.so` now keeps the keys as plaintext `.rodata` strings referenced by pointer tables in `.data.rel.ro`. The JNI wrappers (`getNativeApplicationId` / `getNativeSecret` / `getNativeHost`) dispatch through a 15-row (environment) x 4-column (stage: dev/test/uat/prod) jump table. The script disassembles these helpers, resolves the pointer tables through ELF relocations, labels each row using the gateway hostnames from `getNativeHost`, and picks the production column of the row matching your `--region`.

## VIN key/IV on app >= 1.5.7

Starting with v1.5.7, the VIN AES key/IV are shipped as ECIES-encrypted blobs (base64 strings in the `cj.i` class maps) and are decrypted at runtime by `fi.a` through the iWall security SDK (`SecuritySuite.asymmDecrypt` in `libiwallca.so`). The EC private key lives inside the white-box SDK, so static extraction from the APK is not practical. You have two options:

**Option A (easiest): take them from a v1.5.5 APK.** The VIN key/IV extracted from v1.5.5 are still accepted by the Zeekr API (confirmed against the live API). Download `com.zeekr.global` v1.5.5 (e.g. from APKPure) and run the extractor on it — combine those two values with the other four from your current APK.

**Option B: hook the running app with Frida** (rooted device or emulator):

```js
// vin_hook.js — prints the VIN AES key/IV at runtime
Java.perform(function () {
  var A = Java.use('cj.a');
  A.h.implementation = function (content, key, iv) {
    console.log('VIN key: ' + key);
    console.log('VIN IV:  ' + iv);
    return this.h(content, key, iv);
  };
});
```

```bash
frida -U -l vin_hook.js com.zeekr.global
# then trigger any vehicle API call in the app (e.g. pull to refresh)
```

## Tested Versions

| App | Version | Status |
|---|---|---|
| Zeekr (com.zeekr.global) | 1.5.3 | All 6 secrets extracted successfully |
| Zeekr (com.zeekr.global) | 1.5.5 | All 6 secrets extracted successfully |
| Zeekr EU (com.zeekr.overseas) | 2.9.9 | All 6 secrets extracted successfully (use `--region EU`) |
| Zeekr (com.zeekr.global) | 1.6.0 | 4 of 6 (HMAC + RSA + prod_secret). VIN key/IV: use v1.5.5 APK or Frida — see above |

> **Note:** The `prod_secret` changed between v1.5.3 and v1.5.5. Always extract secrets from the same app version you are running — do not mix secrets from different versions. (Exception: the VIN key/IV from v1.5.5 remain valid for newer app versions, see above.)

> **Tip:** if login succeeds but API calls fail signature validation, try the other `prod_secret` candidates listed in the output — for some regions the working value is not the first candidate.

If you have tested with a different version, please open an issue or PR to update this table.

## Troubleshooting

**"HMAC Access Key: NOT FOUND"** — On app >= 1.5.7 the script prints the available environment rows with their production gateway hosts; pick the row matching your market and check your `--region` flag. On older apps it prints OLLVM candidate values instead. If the layout changed again in a newer APK, please open an issue.

**"VIN Key/IV: NOT FOUND" on app >= 1.5.7** — Expected: these moved behind iWall ECIES and cannot be extracted statically. See [VIN key/IV on app >= 1.5.7](#vin-keyiv-on-app--157).

**"libenv.so not found"** — Make sure you provide the ARM64 split APK (`split_config.arm64_v8a.apk`) as the second argument. The native libraries are in this file, not in the base APK.

**Login fails with the extracted keys** — Try a different `--region` flag. The HMAC keys are region-specific and must match the API gateway your account connects to. Also try the other `prod_secret` candidates from the output.

**APK version changes** — Zeekr may update the app and change how secrets are stored. If the script stops working after an app update, please open an issue.

## Disclaimer

This tool is provided for personal and educational use only. Use it at your own risk. The author is not affiliated with Zeekr or Geely. Reverse engineering may be subject to legal restrictions in your jurisdiction.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Fryyyyy](https://github.com/Fryyyyy) for the [Zeekr Home Assistant integration](https://github.com/Fryyyyy/zeekr_homeassistant) and [Zeekr EV API](https://github.com/Fryyyyy/zeekr_ev_api) library
- [Capstone](https://www.capstone-engine.org/) for the disassembly framework
- [pyelftools](https://github.com/eliben/pyelftools) for ELF parsing
