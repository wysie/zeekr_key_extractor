const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../frida/zeekr_runtime_keys_3x.js'), 'utf8');
const valid = { prod_secret: 'a'.repeat(32), vin_key: 'b'.repeat(16), vin_iv: 'c'.repeat(16) };

function run(values, options = {}) {
  const logs = [];
  const decrypted = [];
  const instance = values === null ? null : {
    k: () => values.prod_secret,
    j: () => { if (options.throwKey) throw new Error('key getter failed'); return values.vin_key; },
    c: () => values.vin_iv,
  };
  const blobs = { prod_secret: 'QUFBQQ==', vin_key: 'QkJCQg==', vin_iv: 'Q0NDQw==' };
  const java = {
    perform: callback => callback(),
    use: name => {
      if (name === 'com.zeekr.snc.log.m') {
        if (options.moved) throw new Error('class moved');
        return { a: { value: instance } };
      }
      if (name === 'yn.a') return { $new: () => ({ c: (env, blob) => {
        decrypted.push(blob);
        const key = Object.keys(blobs).find(key => blobs[key] === blob);
        return key ? (options.badDecrypt ? null : valid[key]) : '<invalid blob>';
      } }) };
      if (name === 'com.geely.snc.security.api.model.EnvType') return { PRODUCT: { value: 'product' } };
      throw new Error('unexpected class: ' + name);
    },
  };
  let code = source;
  if (options.blobs) {
    for (const key of Object.keys(blobs)) {
      const replacement = options.blobs === 'placeholder' ? '<paste blob>' : blobs[key];
      code = code.replace(key + ': null', key + ': ' + JSON.stringify(replacement));
    }
  }
  const context = { console: { log: line => logs.push(String(line)) } };
  if (!options.noJava) context.Java = java;
  vm.runInNewContext(code, context);
  return { logs: logs.join('\n'), decrypted };
}

test('all valid getters produce a complete result without decryption', () => {
  const result = run(valid);
  assert.match(result.logs, /All three runtime values extracted/);
  assert.equal(result.decrypted.length, 0);
  assert.match(result.logs, new RegExp('vin_iv: +'+valid.vin_iv));
});

test('missing VIN values cannot be hidden by a valid prod secret', () => {
  for (const vin_key of [null, undefined, '', 'undefined', '<placeholder key>']) {
    const result = run({ ...valid, vin_key });
    assert.match(result.logs, /Missing runtime values: vin_key/);
    assert.doesNotMatch(result.logs, /All three runtime values extracted/);
    assert.equal(result.decrypted.length, 0);
  }
});

test('one failed getter preserves the other two values and reports the failure', () => {
  const result = run(valid, { throwKey: true });
  assert.match(result.logs, /Missing runtime values: vin_key/);
  assert.match(result.logs, /key getter failed/);
  assert.match(result.logs, new RegExp(valid.vin_iv));
});

test('configured fallback recovers just the missing VIN value', () => {
  const result = run({ ...valid, vin_key: null }, { blobs: true });
  assert.deepEqual(result.decrypted, ['QkJCQg==']);
  assert.match(result.logs, /All three runtime values extracted/);
});

test('moved classes can use configured blobs, but unset/placeholder blobs never run', () => {
  for (const blobs of [false, 'placeholder']) {
    const result = run(null, { moved: true, blobs });
    assert.equal(result.decrypted.length, 0);
    assert.match(result.logs, /Missing runtime values: prod_secret, vin_key, vin_iv/);
    assert.match(result.logs, /class moved/);
  }
  const result = run(null, { moved: true, blobs: true });
  assert.equal(result.decrypted.length, 3);
  assert.match(result.logs, /All three runtime values extracted/);
});

test('a null singleton and invalid decrypted values remain explicit failures', () => {
  const result = run(null, { blobs: true, badDecrypt: true });
  assert.match(result.logs, /Missing runtime values: prod_secret, vin_key, vin_iv/);
  assert.doesNotMatch(result.logs, /All three runtime values extracted/);
});

test('a missing Java bridge gives actionable guidance', () => {
  const result = run(valid, { noJava: true });
  assert.match(result.logs, /Java bridge unavailable/);
  assert.equal(result.decrypted.length, 0);
});
