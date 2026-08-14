// node_modules/@noble/hashes/esm/crypto.js
var crypto2 = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;

// node_modules/@noble/hashes/esm/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  if (hasHexBuiltin)
    return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
var Hash = class {
};
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function randomBytes(bytesLength = 32) {
  if (crypto2 && typeof crypto2.getRandomValues === "function") {
    return crypto2.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto2 && typeof crypto2.randomBytes === "function") {
    return Uint8Array.from(crypto2.randomBytes(bytesLength));
  }
  throw new Error("crypto.getRandomValues must be defined");
}

// node_modules/@noble/hashes/esm/_md.js
function setBigUint64(view, byteOffset, value, isLE) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}
var HashMD = class extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE) {
    super();
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    data = toBytes(data);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);

// node_modules/@noble/hashes/esm/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var shrSH = (h, _l, s) => h >>> s;
var shrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;

// node_modules/@noble/hashes/esm/sha2.js
var K512 = /* @__PURE__ */ (() => split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
var SHA512 = class extends HashMD {
  constructor(outputLen = 64) {
    super(128, outputLen, 16, false);
    this.Ah = SHA512_IV[0] | 0;
    this.Al = SHA512_IV[1] | 0;
    this.Bh = SHA512_IV[2] | 0;
    this.Bl = SHA512_IV[3] | 0;
    this.Ch = SHA512_IV[4] | 0;
    this.Cl = SHA512_IV[5] | 0;
    this.Dh = SHA512_IV[6] | 0;
    this.Dl = SHA512_IV[7] | 0;
    this.Eh = SHA512_IV[8] | 0;
    this.El = SHA512_IV[9] | 0;
    this.Fh = SHA512_IV[10] | 0;
    this.Fl = SHA512_IV[11] | 0;
    this.Gh = SHA512_IV[12] | 0;
    this.Gl = SHA512_IV[13] | 0;
    this.Hh = SHA512_IV[14] | 0;
    this.Hl = SHA512_IV[15] | 0;
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32(offset += 4);
    }
    for (let i = 16; i < 80; i++) {
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
      const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
      const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
      const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i = 0; i < 80; i++) {
      const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
      const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
      const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = add3L(T1l, sigma0l, MAJl);
      Ah = add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    clean(SHA512_W_H, SHA512_W_L);
  }
  destroy() {
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var sha512 = /* @__PURE__ */ createHasher(() => new SHA512());

// node_modules/@noble/curves/esm/utils.js
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
function _abool2(value, title = "") {
  if (typeof value !== "boolean") {
    const prefix = title && `"${title}"`;
    throw new Error(prefix + "expected boolean, got type=" + typeof value);
  }
  return value;
}
function _abytes2(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
  }
  return value;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  abytes(bytes);
  return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      throw new Error(title + " must be hex string or Uint8Array, cause: " + e);
    }
  } else if (isBytes(hex)) {
    res = Uint8Array.from(hex);
  } else {
    throw new Error(title + " must be hex string or Uint8Array");
  }
  const len = res.length;
  if (typeof expectedLength === "number" && len !== expectedLength)
    throw new Error(title + " of length " + expectedLength + " expected, got " + len);
  return res;
}
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function copyBytes(bytes) {
  return Uint8Array.from(bytes);
}
var isPosBig = (n) => typeof n === "bigint" && _0n <= n;
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new Error("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  let len;
  for (len = 0; n > _0n; n >>= _1n, len += 1)
    ;
  return len;
}
var bitMask = (n) => (_1n << BigInt(n)) - _1n;
function _validateObject(object, fields, optFields = {}) {
  if (!object || typeof object !== "object")
    throw new Error("expected valid options object");
  function checkField(fieldName, expectedType, isOpt) {
    const val = object[fieldName];
    if (isOpt && val === void 0)
      return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new Error(`param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`);
  }
  Object.entries(fields).forEach(([k, v]) => checkField(k, v, false));
  Object.entries(optFields).forEach(([k, v]) => checkField(k, v, true));
}
var notImplemented = () => {
  throw new Error("not implemented");
};
function memoized(fn) {
  const map = /* @__PURE__ */ new WeakMap();
  return (arg, ...args) => {
    const val = map.get(arg);
    if (val !== void 0)
      return val;
    const computed = fn(arg, ...args);
    map.set(arg, computed);
    return computed;
  };
}

// node_modules/@noble/curves/esm/abstract/modular.js
var _0n2 = BigInt(0);
var _1n2 = BigInt(1);
var _2n = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _7n = /* @__PURE__ */ BigInt(7);
var _8n = /* @__PURE__ */ BigInt(8);
var _9n = /* @__PURE__ */ BigInt(9);
var _16n = /* @__PURE__ */ BigInt(16);
function mod(a, b) {
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow2(x, power, modulo) {
  let res = x;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number, modulo) {
  if (number === _0n2)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _0n2)
    throw new Error("invert: expected positive modulus, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n2, y = _1n2, u = _1n2, v = _0n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function assertIsSquare(Fp2, root, n) {
  if (!Fp2.eql(Fp2.sqr(root), n))
    throw new Error("Cannot find square root");
}
function sqrt3mod4(Fp2, n) {
  const p1div4 = (Fp2.ORDER + _1n2) / _4n;
  const root = Fp2.pow(n, p1div4);
  assertIsSquare(Fp2, root, n);
  return root;
}
function sqrt5mod8(Fp2, n) {
  const p5div8 = (Fp2.ORDER - _5n) / _8n;
  const n2 = Fp2.mul(n, _2n);
  const v = Fp2.pow(n2, p5div8);
  const nv = Fp2.mul(n, v);
  const i = Fp2.mul(Fp2.mul(nv, _2n), v);
  const root = Fp2.mul(nv, Fp2.sub(i, Fp2.ONE));
  assertIsSquare(Fp2, root, n);
  return root;
}
function sqrt9mod16(P) {
  const Fp_ = Field(P);
  const tn = tonelliShanks(P);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
  const c2 = tn(Fp_, c1);
  const c3 = tn(Fp_, Fp_.neg(c1));
  const c4 = (P + _7n) / _16n;
  return (Fp2, n) => {
    let tv1 = Fp2.pow(n, c4);
    let tv2 = Fp2.mul(tv1, c1);
    const tv3 = Fp2.mul(tv1, c2);
    const tv4 = Fp2.mul(tv1, c3);
    const e1 = Fp2.eql(Fp2.sqr(tv2), n);
    const e2 = Fp2.eql(Fp2.sqr(tv3), n);
    tv1 = Fp2.cmov(tv1, tv2, e1);
    tv2 = Fp2.cmov(tv4, tv3, e2);
    const e3 = Fp2.eql(Fp2.sqr(tv2), n);
    const root = Fp2.cmov(tv1, tv2, e3);
    assertIsSquare(Fp2, root, n);
    return root;
  };
}
function tonelliShanks(P) {
  if (P < _3n)
    throw new Error("sqrt is not defined for small field");
  let Q = P - _1n2;
  let S = 0;
  while (Q % _2n === _0n2) {
    Q /= _2n;
    S++;
  }
  let Z = _2n;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q);
  const Q1div2 = (Q + _1n2) / _2n;
  return function tonelliSlow(Fp2, n) {
    if (Fp2.is0(n))
      return n;
    if (FpLegendre(Fp2, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = Fp2.mul(Fp2.ONE, cc);
    let t = Fp2.pow(n, Q);
    let R = Fp2.pow(n, Q1div2);
    while (!Fp2.eql(t, Fp2.ONE)) {
      if (Fp2.is0(t))
        return Fp2.ZERO;
      let i = 1;
      let t_tmp = Fp2.sqr(t);
      while (!Fp2.eql(t_tmp, Fp2.ONE)) {
        i++;
        t_tmp = Fp2.sqr(t_tmp);
        if (i === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n2 << BigInt(M - i - 1);
      const b = Fp2.pow(c, exponent);
      M = i;
      c = Fp2.sqr(b);
      t = Fp2.mul(t, c);
      R = Fp2.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P) {
  if (P % _4n === _3n)
    return sqrt3mod4;
  if (P % _8n === _5n)
    return sqrt5mod8;
  if (P % _16n === _9n)
    return sqrt9mod16(P);
  return tonelliShanks(P);
}
var isNegativeLE = (num, modulo) => (mod(num, modulo) & _1n2) === _1n2;
var FIELD_FIELDS = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function validateField(field) {
  const initial = {
    ORDER: "bigint",
    MASK: "bigint",
    BYTES: "number",
    BITS: "number"
  };
  const opts = FIELD_FIELDS.reduce((map, val) => {
    map[val] = "function";
    return map;
  }, initial);
  _validateObject(field, opts);
  return field;
}
function FpPow(Fp2, num, power) {
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n2)
    return Fp2.ONE;
  if (power === _1n2)
    return num;
  let p = Fp2.ONE;
  let d = num;
  while (power > _0n2) {
    if (power & _1n2)
      p = Fp2.mul(p, d);
    d = Fp2.sqr(d);
    power >>= _1n2;
  }
  return p;
}
function FpInvertBatch(Fp2, nums, passZero = false) {
  const inverted = new Array(nums.length).fill(passZero ? Fp2.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i] = acc;
    return Fp2.mul(acc, num);
  }, Fp2.ONE);
  const invertedAcc = Fp2.inv(multipliedAcc);
  nums.reduceRight((acc, num, i) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i] = Fp2.mul(acc, inverted[i]);
    return Fp2.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp2, n) {
  const p1mod2 = (Fp2.ORDER - _1n2) / _2n;
  const powered = Fp2.pow(n, p1mod2);
  const yes = Fp2.eql(powered, Fp2.ONE);
  const zero = Fp2.eql(powered, Fp2.ZERO);
  const no = Fp2.eql(powered, Fp2.neg(Fp2.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber(nBitLength);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
function Field(ORDER, bitLenOrOpts, isLE = false, opts = {}) {
  if (ORDER <= _0n2)
    throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
  let _nbitLength = void 0;
  let _sqrt = void 0;
  let modFromBytes = false;
  let allowedLengths = void 0;
  if (typeof bitLenOrOpts === "object" && bitLenOrOpts != null) {
    if (opts.sqrt || isLE)
      throw new Error("cannot specify opts in two arguments");
    const _opts = bitLenOrOpts;
    if (_opts.BITS)
      _nbitLength = _opts.BITS;
    if (_opts.sqrt)
      _sqrt = _opts.sqrt;
    if (typeof _opts.isLE === "boolean")
      isLE = _opts.isLE;
    if (typeof _opts.modFromBytes === "boolean")
      modFromBytes = _opts.modFromBytes;
    allowedLengths = _opts.allowedLengths;
  } else {
    if (typeof bitLenOrOpts === "number")
      _nbitLength = bitLenOrOpts;
    if (opts.sqrt)
      _sqrt = opts.sqrt;
  }
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, _nbitLength);
  if (BYTES > 2048)
    throw new Error("invalid field: expected ORDER of <= 2048 bytes");
  let sqrtP;
  const f = Object.freeze({
    ORDER,
    isLE,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n2,
    ONE: _1n2,
    allowedLengths,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== "bigint")
        throw new Error("invalid field element: expected bigint, got " + typeof num);
      return _0n2 <= num && num < ORDER;
    },
    is0: (num) => num === _0n2,
    // is valid and invertible
    isValidNot0: (num) => !f.is0(num) && f.isValid(num),
    isOdd: (num) => (num & _1n2) === _1n2,
    neg: (num) => mod(-num, ORDER),
    eql: (lhs, rhs) => lhs === rhs,
    sqr: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
    // Same as above, but doesn't normalize
    sqrN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,
    inv: (num) => invert(num, ORDER),
    sqrt: _sqrt || ((n) => {
      if (!sqrtP)
        sqrtP = FpSqrt(ORDER);
      return sqrtP(f, n);
    }),
    toBytes: (num) => isLE ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES),
    fromBytes: (bytes, skipValidation = true) => {
      if (allowedLengths) {
        if (!allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
          throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
        }
        const padded = new Uint8Array(BYTES);
        padded.set(bytes, isLE ? 0 : padded.length - bytes.length);
        bytes = padded;
      }
      if (bytes.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
      let scalar = isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
      if (modFromBytes)
        scalar = mod(scalar, ORDER);
      if (!skipValidation) {
        if (!f.isValid(scalar))
          throw new Error("invalid field element: outside of range 0..ORDER");
      }
      return scalar;
    },
    // TODO: we don't need it here, move out to separate fn
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // We can't move this out because Fp6, Fp12 implement it
    // and it's unclear what to return in there.
    cmov: (a, b, c) => c ? b : a
  });
  return Object.freeze(f);
}

// node_modules/@noble/curves/esm/abstract/curve.js
var _0n3 = BigInt(0);
var _1n3 = BigInt(1);
function negateCt(condition, item) {
  const neg = item.negate();
  return condition ? neg : item;
}
function normalizeZ(c, points) {
  const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
  return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}
function validateW(W, bits) {
  if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
    throw new Error("invalid window size, expected [1.." + bits + "], got W=" + W);
}
function calcWOpts(W, scalarBits) {
  validateW(W, scalarBits);
  const windows = Math.ceil(scalarBits / W) + 1;
  const windowSize = 2 ** (W - 1);
  const maxNumber = 2 ** W;
  const mask = bitMask(W);
  const shiftBy = BigInt(W);
  return { windows, windowSize, mask, maxNumber, shiftBy };
}
function calcOffsets(n, window, wOpts) {
  const { windowSize, mask, maxNumber, shiftBy } = wOpts;
  let wbits = Number(n & mask);
  let nextN = n >> shiftBy;
  if (wbits > windowSize) {
    wbits -= maxNumber;
    nextN += _1n3;
  }
  const offsetStart = window * windowSize;
  const offset = offsetStart + Math.abs(wbits) - 1;
  const isZero = wbits === 0;
  const isNeg = wbits < 0;
  const isNegF = window % 2 !== 0;
  const offsetF = offsetStart;
  return { nextN, offset, isZero, isNeg, isNegF, offsetF };
}
function validateMSMPoints(points, c) {
  if (!Array.isArray(points))
    throw new Error("array expected");
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i);
  });
}
function validateMSMScalars(scalars, field) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i) => {
    if (!field.isValid(s))
      throw new Error("invalid scalar at index " + i);
  });
}
var pointPrecomputes = /* @__PURE__ */ new WeakMap();
var pointWindowSizes = /* @__PURE__ */ new WeakMap();
function getW(P) {
  return pointWindowSizes.get(P) || 1;
}
function assert0(n) {
  if (n !== _0n3)
    throw new Error("invalid wNAF");
}
var wNAF = class {
  // Parametrized with a given Point class (not individual point)
  constructor(Point, bits) {
    this.BASE = Point.BASE;
    this.ZERO = Point.ZERO;
    this.Fn = Point.Fn;
    this.bits = bits;
  }
  // non-const time multiplication ladder
  _unsafeLadder(elm, n, p = this.ZERO) {
    let d = elm;
    while (n > _0n3) {
      if (n & _1n3)
        p = p.add(d);
      d = d.double();
      n >>= _1n3;
    }
    return p;
  }
  /**
   * Creates a wNAF precomputation window. Used for caching.
   * Default window size is set by `utils.precompute()` and is equal to 8.
   * Number of precomputed points depends on the curve size:
   * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
   * - 𝑊 is the window size
   * - 𝑛 is the bitlength of the curve order.
   * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
   * @param point Point instance
   * @param W window size
   * @returns precomputed point tables flattened to a single array
   */
  precomputeWindow(point, W) {
    const { windows, windowSize } = calcWOpts(W, this.bits);
    const points = [];
    let p = point;
    let base = p;
    for (let window = 0; window < windows; window++) {
      base = p;
      points.push(base);
      for (let i = 1; i < windowSize; i++) {
        base = base.add(p);
        points.push(base);
      }
      p = base.double();
    }
    return points;
  }
  /**
   * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
   * More compact implementation:
   * https://github.com/paulmillr/noble-secp256k1/blob/47cb1669b6e506ad66b35fe7d76132ae97465da2/index.ts#L502-L541
   * @returns real and fake (for const-time) points
   */
  wNAF(W, precomputes, n) {
    if (!this.Fn.isValid(n))
      throw new Error("invalid scalar");
    let p = this.ZERO;
    let f = this.BASE;
    const wo = calcWOpts(W, this.bits);
    for (let window = 0; window < wo.windows; window++) {
      const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
      n = nextN;
      if (isZero) {
        f = f.add(negateCt(isNegF, precomputes[offsetF]));
      } else {
        p = p.add(negateCt(isNeg, precomputes[offset]));
      }
    }
    assert0(n);
    return { p, f };
  }
  /**
   * Implements ec unsafe (non const-time) multiplication using precomputed tables and w-ary non-adjacent form.
   * @param acc accumulator point to add result of multiplication
   * @returns point
   */
  wNAFUnsafe(W, precomputes, n, acc = this.ZERO) {
    const wo = calcWOpts(W, this.bits);
    for (let window = 0; window < wo.windows; window++) {
      if (n === _0n3)
        break;
      const { nextN, offset, isZero, isNeg } = calcOffsets(n, window, wo);
      n = nextN;
      if (isZero) {
        continue;
      } else {
        const item = precomputes[offset];
        acc = acc.add(isNeg ? item.negate() : item);
      }
    }
    assert0(n);
    return acc;
  }
  getPrecomputes(W, point, transform) {
    let comp = pointPrecomputes.get(point);
    if (!comp) {
      comp = this.precomputeWindow(point, W);
      if (W !== 1) {
        if (typeof transform === "function")
          comp = transform(comp);
        pointPrecomputes.set(point, comp);
      }
    }
    return comp;
  }
  cached(point, scalar, transform) {
    const W = getW(point);
    return this.wNAF(W, this.getPrecomputes(W, point, transform), scalar);
  }
  unsafe(point, scalar, transform, prev) {
    const W = getW(point);
    if (W === 1)
      return this._unsafeLadder(point, scalar, prev);
    return this.wNAFUnsafe(W, this.getPrecomputes(W, point, transform), scalar, prev);
  }
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  createCache(P, W) {
    validateW(W, this.bits);
    pointWindowSizes.set(P, W);
    pointPrecomputes.delete(P);
  }
  hasCache(elm) {
    return getW(elm) !== 1;
  }
};
function pippenger(c, fieldN, points, scalars) {
  validateMSMPoints(points, c);
  validateMSMScalars(scalars, fieldN);
  const plength = points.length;
  const slength = scalars.length;
  if (plength !== slength)
    throw new Error("arrays of points and scalars must have equal length");
  const zero = c.ZERO;
  const wbits = bitLen(BigInt(plength));
  let windowSize = 1;
  if (wbits > 12)
    windowSize = wbits - 3;
  else if (wbits > 4)
    windowSize = wbits - 2;
  else if (wbits > 0)
    windowSize = 2;
  const MASK = bitMask(windowSize);
  const buckets = new Array(Number(MASK) + 1).fill(zero);
  const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
  let sum = zero;
  for (let i = lastBits; i >= 0; i -= windowSize) {
    buckets.fill(zero);
    for (let j = 0; j < slength; j++) {
      const scalar = scalars[j];
      const wbits2 = Number(scalar >> BigInt(i) & MASK);
      buckets[wbits2] = buckets[wbits2].add(points[j]);
    }
    let resI = zero;
    for (let j = buckets.length - 1, sumI = zero; j > 0; j--) {
      sumI = sumI.add(buckets[j]);
      resI = resI.add(sumI);
    }
    sum = sum.add(resI);
    if (i !== 0)
      for (let j = 0; j < windowSize; j++)
        sum = sum.double();
  }
  return sum;
}
function createField(order, field, isLE) {
  if (field) {
    if (field.ORDER !== order)
      throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
    validateField(field);
    return field;
  } else {
    return Field(order, { isLE });
  }
}
function _createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
  if (FpFnLE === void 0)
    FpFnLE = type === "edwards";
  if (!CURVE || typeof CURVE !== "object")
    throw new Error(`expected valid ${type} CURVE object`);
  for (const p of ["p", "n", "h"]) {
    const val = CURVE[p];
    if (!(typeof val === "bigint" && val > _0n3))
      throw new Error(`CURVE.${p} must be positive bigint`);
  }
  const Fp2 = createField(CURVE.p, curveOpts.Fp, FpFnLE);
  const Fn2 = createField(CURVE.n, curveOpts.Fn, FpFnLE);
  const _b = type === "weierstrass" ? "b" : "d";
  const params = ["Gx", "Gy", "a", _b];
  for (const p of params) {
    if (!Fp2.isValid(CURVE[p]))
      throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
  }
  CURVE = Object.freeze(Object.assign({}, CURVE));
  return { CURVE, Fp: Fp2, Fn: Fn2 };
}

// node_modules/@noble/curves/esm/abstract/edwards.js
var _0n4 = BigInt(0);
var _1n4 = BigInt(1);
var _2n2 = BigInt(2);
var _8n2 = BigInt(8);
function isEdValidXY(Fp2, CURVE, x, y) {
  const x2 = Fp2.sqr(x);
  const y2 = Fp2.sqr(y);
  const left = Fp2.add(Fp2.mul(CURVE.a, x2), y2);
  const right = Fp2.add(Fp2.ONE, Fp2.mul(CURVE.d, Fp2.mul(x2, y2)));
  return Fp2.eql(left, right);
}
function edwards(params, extraOpts = {}) {
  const validated = _createCurveFields("edwards", params, extraOpts, extraOpts.FpFnLE);
  const { Fp: Fp2, Fn: Fn2 } = validated;
  let CURVE = validated.CURVE;
  const { h: cofactor } = CURVE;
  _validateObject(extraOpts, {}, { uvRatio: "function" });
  const MASK = _2n2 << BigInt(Fn2.BYTES * 8) - _1n4;
  const modP = (n) => Fp2.create(n);
  const uvRatio2 = extraOpts.uvRatio || ((u, v) => {
    try {
      return { isValid: true, value: Fp2.sqrt(Fp2.div(u, v)) };
    } catch (e) {
      return { isValid: false, value: _0n4 };
    }
  });
  if (!isEdValidXY(Fp2, CURVE, CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  function acoord(title, n, banZero = false) {
    const min = banZero ? _1n4 : _0n4;
    aInRange("coordinate " + title, n, min, MASK);
    return n;
  }
  function aextpoint(other) {
    if (!(other instanceof Point))
      throw new Error("ExtendedPoint expected");
  }
  const toAffineMemo = memoized((p, iz) => {
    const { X, Y, Z } = p;
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? _8n2 : Fp2.inv(Z);
    const x = modP(X * iz);
    const y = modP(Y * iz);
    const zz = Fp2.mul(Z, iz);
    if (is0)
      return { x: _0n4, y: _1n4 };
    if (zz !== _1n4)
      throw new Error("invZ was invalid");
    return { x, y };
  });
  const assertValidMemo = memoized((p) => {
    const { a, d } = CURVE;
    if (p.is0())
      throw new Error("bad point: ZERO");
    const { X, Y, Z, T } = p;
    const X2 = modP(X * X);
    const Y2 = modP(Y * Y);
    const Z2 = modP(Z * Z);
    const Z4 = modP(Z2 * Z2);
    const aX2 = modP(X2 * a);
    const left = modP(Z2 * modP(aX2 + Y2));
    const right = modP(Z4 + modP(d * modP(X2 * Y2)));
    if (left !== right)
      throw new Error("bad point: equation left != right (1)");
    const XY = modP(X * Y);
    const ZT = modP(Z * T);
    if (XY !== ZT)
      throw new Error("bad point: equation left != right (2)");
    return true;
  });
  class Point {
    constructor(X, Y, Z, T) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y);
      this.Z = acoord("z", Z, true);
      this.T = acoord("t", T);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    static fromAffine(p) {
      if (p instanceof Point)
        throw new Error("extended point not allowed");
      const { x, y } = p || {};
      acoord("x", x);
      acoord("y", y);
      return new Point(x, y, _1n4, modP(x * y));
    }
    // Uses algo from RFC8032 5.1.3.
    static fromBytes(bytes, zip215 = false) {
      const len = Fp2.BYTES;
      const { a, d } = CURVE;
      bytes = copyBytes(_abytes2(bytes, len, "point"));
      _abool2(zip215, "zip215");
      const normed = copyBytes(bytes);
      const lastByte = bytes[len - 1];
      normed[len - 1] = lastByte & ~128;
      const y = bytesToNumberLE(normed);
      const max = zip215 ? MASK : Fp2.ORDER;
      aInRange("point.y", y, _0n4, max);
      const y2 = modP(y * y);
      const u = modP(y2 - _1n4);
      const v = modP(d * y2 - a);
      let { isValid, value: x } = uvRatio2(u, v);
      if (!isValid)
        throw new Error("bad point: invalid y coordinate");
      const isXOdd = (x & _1n4) === _1n4;
      const isLastByteOdd = (lastByte & 128) !== 0;
      if (!zip215 && x === _0n4 && isLastByteOdd)
        throw new Error("bad point: x=0 and x_0=1");
      if (isLastByteOdd !== isXOdd)
        x = modP(-x);
      return Point.fromAffine({ x, y });
    }
    static fromHex(bytes, zip215 = false) {
      return Point.fromBytes(ensureBytes("point", bytes), zip215);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    precompute(windowSize = 8, isLazy = true) {
      wnaf.createCache(this, windowSize);
      if (!isLazy)
        this.multiply(_2n2);
      return this;
    }
    // Useful in fromAffine() - not for fromBytes(), which always created valid points.
    assertValidity() {
      assertValidMemo(this);
    }
    // Compare one point to another.
    equals(other) {
      aextpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const X1Z2 = modP(X1 * Z2);
      const X2Z1 = modP(X2 * Z1);
      const Y1Z2 = modP(Y1 * Z2);
      const Y2Z1 = modP(Y2 * Z1);
      return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    negate() {
      return new Point(modP(-this.X), this.Y, this.Z, modP(-this.T));
    }
    // Fast algo for doubling Extended Point.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // Cost: 4M + 4S + 1*a + 6add + 1*2.
    double() {
      const { a } = CURVE;
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const A = modP(X1 * X1);
      const B = modP(Y1 * Y1);
      const C = modP(_2n2 * modP(Z1 * Z1));
      const D = modP(a * A);
      const x1y1 = X1 + Y1;
      const E = modP(modP(x1y1 * x1y1) - A - B);
      const G = D + B;
      const F = G - C;
      const H = D - B;
      const X3 = modP(E * F);
      const Y3 = modP(G * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G);
      return new Point(X3, Y3, Z3, T3);
    }
    // Fast algo for adding 2 Extended Points.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // Cost: 9M + 1*a + 1*d + 7add.
    add(other) {
      aextpoint(other);
      const { a, d } = CURVE;
      const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
      const { X: X2, Y: Y2, Z: Z2, T: T2 } = other;
      const A = modP(X1 * X2);
      const B = modP(Y1 * Y2);
      const C = modP(T1 * d * T2);
      const D = modP(Z1 * Z2);
      const E = modP((X1 + Y1) * (X2 + Y2) - A - B);
      const F = D - C;
      const G = D + C;
      const H = modP(B - a * A);
      const X3 = modP(E * F);
      const Y3 = modP(G * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G);
      return new Point(X3, Y3, Z3, T3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    // Constant-time multiplication.
    multiply(scalar) {
      if (!Fn2.isValidNot0(scalar))
        throw new Error("invalid scalar: expected 1 <= sc < curve.n");
      const { p, f } = wnaf.cached(this, scalar, (p2) => normalizeZ(Point, p2));
      return normalizeZ(Point, [p, f])[0];
    }
    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    // Does NOT allow scalars higher than CURVE.n.
    // Accepts optional accumulator to merge with multiply (important for sparse scalars)
    multiplyUnsafe(scalar, acc = Point.ZERO) {
      if (!Fn2.isValid(scalar))
        throw new Error("invalid scalar: expected 0 <= sc < curve.n");
      if (scalar === _0n4)
        return Point.ZERO;
      if (this.is0() || scalar === _1n4)
        return this;
      return wnaf.unsafe(this, scalar, (p) => normalizeZ(Point, p), acc);
    }
    // Checks if point is of small order.
    // If you add something to small order point, you will have "dirty"
    // point with torsion component.
    // Multiplies point by cofactor and checks if the result is 0.
    isSmallOrder() {
      return this.multiplyUnsafe(cofactor).is0();
    }
    // Multiplies point by curve order and checks if the result is 0.
    // Returns `false` is the point is dirty.
    isTorsionFree() {
      return wnaf.unsafe(this, CURVE.n).is0();
    }
    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(invertedZ) {
      return toAffineMemo(this, invertedZ);
    }
    clearCofactor() {
      if (cofactor === _1n4)
        return this;
      return this.multiplyUnsafe(cofactor);
    }
    toBytes() {
      const { x, y } = this.toAffine();
      const bytes = Fp2.toBytes(y);
      bytes[bytes.length - 1] |= x & _1n4 ? 128 : 0;
      return bytes;
    }
    toHex() {
      return bytesToHex(this.toBytes());
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
    // TODO: remove
    get ex() {
      return this.X;
    }
    get ey() {
      return this.Y;
    }
    get ez() {
      return this.Z;
    }
    get et() {
      return this.T;
    }
    static normalizeZ(points) {
      return normalizeZ(Point, points);
    }
    static msm(points, scalars) {
      return pippenger(Point, Fn2, points, scalars);
    }
    _setWindowSize(windowSize) {
      this.precompute(windowSize);
    }
    toRawBytes() {
      return this.toBytes();
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, _1n4, modP(CURVE.Gx * CURVE.Gy));
  Point.ZERO = new Point(_0n4, _1n4, _1n4, _0n4);
  Point.Fp = Fp2;
  Point.Fn = Fn2;
  const wnaf = new wNAF(Point, Fn2.BITS);
  Point.BASE.precompute(8);
  return Point;
}
var PrimeEdwardsPoint = class {
  constructor(ep) {
    this.ep = ep;
  }
  // Static methods that must be implemented by subclasses
  static fromBytes(_bytes) {
    notImplemented();
  }
  static fromHex(_hex) {
    notImplemented();
  }
  get x() {
    return this.toAffine().x;
  }
  get y() {
    return this.toAffine().y;
  }
  // Common implementations
  clearCofactor() {
    return this;
  }
  assertValidity() {
    this.ep.assertValidity();
  }
  toAffine(invertedZ) {
    return this.ep.toAffine(invertedZ);
  }
  toHex() {
    return bytesToHex(this.toBytes());
  }
  toString() {
    return this.toHex();
  }
  isTorsionFree() {
    return true;
  }
  isSmallOrder() {
    return false;
  }
  add(other) {
    this.assertSame(other);
    return this.init(this.ep.add(other.ep));
  }
  subtract(other) {
    this.assertSame(other);
    return this.init(this.ep.subtract(other.ep));
  }
  multiply(scalar) {
    return this.init(this.ep.multiply(scalar));
  }
  multiplyUnsafe(scalar) {
    return this.init(this.ep.multiplyUnsafe(scalar));
  }
  double() {
    return this.init(this.ep.double());
  }
  negate() {
    return this.init(this.ep.negate());
  }
  precompute(windowSize, isLazy) {
    return this.init(this.ep.precompute(windowSize, isLazy));
  }
  /** @deprecated use `toBytes` */
  toRawBytes() {
    return this.toBytes();
  }
};
function eddsa(Point, cHash, eddsaOpts = {}) {
  if (typeof cHash !== "function")
    throw new Error('"hash" function param is required');
  _validateObject(eddsaOpts, {}, {
    adjustScalarBytes: "function",
    randomBytes: "function",
    domain: "function",
    prehash: "function",
    mapToCurve: "function"
  });
  const { prehash } = eddsaOpts;
  const { BASE, Fp: Fp2, Fn: Fn2 } = Point;
  const randomBytes2 = eddsaOpts.randomBytes || randomBytes;
  const adjustScalarBytes2 = eddsaOpts.adjustScalarBytes || ((bytes) => bytes);
  const domain = eddsaOpts.domain || ((data, ctx, phflag) => {
    _abool2(phflag, "phflag");
    if (ctx.length || phflag)
      throw new Error("Contexts/pre-hash are not supported");
    return data;
  });
  function modN_LE(hash) {
    return Fn2.create(bytesToNumberLE(hash));
  }
  function getPrivateScalar(key) {
    const len = lengths.secretKey;
    key = ensureBytes("private key", key, len);
    const hashed = ensureBytes("hashed private key", cHash(key), 2 * len);
    const head = adjustScalarBytes2(hashed.slice(0, len));
    const prefix = hashed.slice(len, 2 * len);
    const scalar = modN_LE(head);
    return { head, prefix, scalar };
  }
  function getExtendedPublicKey(secretKey) {
    const { head, prefix, scalar } = getPrivateScalar(secretKey);
    const point = BASE.multiply(scalar);
    const pointBytes = point.toBytes();
    return { head, prefix, scalar, point, pointBytes };
  }
  function getPublicKey(secretKey) {
    return getExtendedPublicKey(secretKey).pointBytes;
  }
  function hashDomainToScalar(context = Uint8Array.of(), ...msgs) {
    const msg = concatBytes(...msgs);
    return modN_LE(cHash(domain(msg, ensureBytes("context", context), !!prehash)));
  }
  function sign(msg, secretKey, options = {}) {
    msg = ensureBytes("message", msg);
    if (prehash)
      msg = prehash(msg);
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(secretKey);
    const r = hashDomainToScalar(options.context, prefix, msg);
    const R = BASE.multiply(r).toBytes();
    const k = hashDomainToScalar(options.context, R, pointBytes, msg);
    const s = Fn2.create(r + k * scalar);
    if (!Fn2.isValid(s))
      throw new Error("sign failed: invalid s");
    const rs = concatBytes(R, Fn2.toBytes(s));
    return _abytes2(rs, lengths.signature, "result");
  }
  const verifyOpts = { zip215: true };
  function verify(sig, msg, publicKey, options = verifyOpts) {
    const { context, zip215 } = options;
    const len = lengths.signature;
    sig = ensureBytes("signature", sig, len);
    msg = ensureBytes("message", msg);
    publicKey = ensureBytes("publicKey", publicKey, lengths.publicKey);
    if (zip215 !== void 0)
      _abool2(zip215, "zip215");
    if (prehash)
      msg = prehash(msg);
    const mid = len / 2;
    const r = sig.subarray(0, mid);
    const s = bytesToNumberLE(sig.subarray(mid, len));
    let A, R, SB;
    try {
      A = Point.fromBytes(publicKey, zip215);
      R = Point.fromBytes(r, zip215);
      SB = BASE.multiplyUnsafe(s);
    } catch (error) {
      return false;
    }
    if (!zip215 && A.isSmallOrder())
      return false;
    const k = hashDomainToScalar(context, R.toBytes(), A.toBytes(), msg);
    const RkA = R.add(A.multiplyUnsafe(k));
    return RkA.subtract(SB).clearCofactor().is0();
  }
  const _size = Fp2.BYTES;
  const lengths = {
    secretKey: _size,
    publicKey: _size,
    signature: 2 * _size,
    seed: _size
  };
  function randomSecretKey(seed = randomBytes2(lengths.seed)) {
    return _abytes2(seed, lengths.seed, "seed");
  }
  function keygen(seed) {
    const secretKey = utils.randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  }
  function isValidSecretKey(key) {
    return isBytes(key) && key.length === Fn2.BYTES;
  }
  function isValidPublicKey(key, zip215) {
    try {
      return !!Point.fromBytes(key, zip215);
    } catch (error) {
      return false;
    }
  }
  const utils = {
    getExtendedPublicKey,
    randomSecretKey,
    isValidSecretKey,
    isValidPublicKey,
    /**
     * Converts ed public key to x public key. Uses formula:
     * - ed25519:
     *   - `(u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)`
     *   - `(x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))`
     * - ed448:
     *   - `(u, v) = ((y-1)/(y+1), sqrt(156324)*u/x)`
     *   - `(x, y) = (sqrt(156324)*u/v, (1+u)/(1-u))`
     */
    toMontgomery(publicKey) {
      const { y } = Point.fromBytes(publicKey);
      const size = lengths.publicKey;
      const is25519 = size === 32;
      if (!is25519 && size !== 57)
        throw new Error("only defined for 25519 and 448");
      const u = is25519 ? Fp2.div(_1n4 + y, _1n4 - y) : Fp2.div(y - _1n4, y + _1n4);
      return Fp2.toBytes(u);
    },
    toMontgomerySecret(secretKey) {
      const size = lengths.secretKey;
      _abytes2(secretKey, size);
      const hashed = cHash(secretKey.subarray(0, size));
      return adjustScalarBytes2(hashed).subarray(0, size);
    },
    /** @deprecated */
    randomPrivateKey: randomSecretKey,
    /** @deprecated */
    precompute(windowSize = 8, point = Point.BASE) {
      return point.precompute(windowSize, false);
    }
  };
  return Object.freeze({
    keygen,
    getPublicKey,
    sign,
    verify,
    utils,
    Point,
    lengths
  });
}
function _eddsa_legacy_opts_to_new(c) {
  const CURVE = {
    a: c.a,
    d: c.d,
    p: c.Fp.ORDER,
    n: c.n,
    h: c.h,
    Gx: c.Gx,
    Gy: c.Gy
  };
  const Fp2 = c.Fp;
  const Fn2 = Field(CURVE.n, c.nBitLength, true);
  const curveOpts = { Fp: Fp2, Fn: Fn2, uvRatio: c.uvRatio };
  const eddsaOpts = {
    randomBytes: c.randomBytes,
    adjustScalarBytes: c.adjustScalarBytes,
    domain: c.domain,
    prehash: c.prehash,
    mapToCurve: c.mapToCurve
  };
  return { CURVE, curveOpts, hash: c.hash, eddsaOpts };
}
function _eddsa_new_output_to_legacy(c, eddsa2) {
  const Point = eddsa2.Point;
  const legacy = Object.assign({}, eddsa2, {
    ExtendedPoint: Point,
    CURVE: c,
    nBitLength: Point.Fn.BITS,
    nByteLength: Point.Fn.BYTES
  });
  return legacy;
}
function twistedEdwards(c) {
  const { CURVE, curveOpts, hash, eddsaOpts } = _eddsa_legacy_opts_to_new(c);
  const Point = edwards(CURVE, curveOpts);
  const EDDSA = eddsa(Point, hash, eddsaOpts);
  return _eddsa_new_output_to_legacy(c, EDDSA);
}

// node_modules/@noble/curves/esm/ed25519.js
var _0n5 = /* @__PURE__ */ BigInt(0);
var _1n5 = BigInt(1);
var _2n3 = BigInt(2);
var _3n2 = BigInt(3);
var _5n2 = BigInt(5);
var _8n3 = BigInt(8);
var ed25519_CURVE_p = BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
var ed25519_CURVE = /* @__PURE__ */ (() => ({
  p: ed25519_CURVE_p,
  n: BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
  h: _8n3,
  a: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
  d: BigInt("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
  Gx: BigInt("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
  Gy: BigInt("0x6666666666666666666666666666666666666666666666666666666666666658")
}))();
function ed25519_pow_2_252_3(x) {
  const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
  const P = ed25519_CURVE_p;
  const x2 = x * x % P;
  const b2 = x2 * x % P;
  const b4 = pow2(b2, _2n3, P) * b2 % P;
  const b5 = pow2(b4, _1n5, P) * x % P;
  const b10 = pow2(b5, _5n2, P) * b5 % P;
  const b20 = pow2(b10, _10n, P) * b10 % P;
  const b40 = pow2(b20, _20n, P) * b20 % P;
  const b80 = pow2(b40, _40n, P) * b40 % P;
  const b160 = pow2(b80, _80n, P) * b80 % P;
  const b240 = pow2(b160, _80n, P) * b80 % P;
  const b250 = pow2(b240, _10n, P) * b10 % P;
  const pow_p_5_8 = pow2(b250, _2n3, P) * x % P;
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes) {
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes;
}
var ED25519_SQRT_M1 = /* @__PURE__ */ BigInt("19681161376707505956807079304988542015446066515923890162744021073123829784752");
function uvRatio(u, v) {
  const P = ed25519_CURVE_p;
  const v3 = mod(v * v * v, P);
  const v7 = mod(v3 * v3 * v, P);
  const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
  let x = mod(u * v3 * pow, P);
  const vx2 = mod(v * x * x, P);
  const root1 = x;
  const root2 = mod(x * ED25519_SQRT_M1, P);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === mod(-u, P);
  const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P);
  if (useRoot1)
    x = root1;
  if (useRoot2 || noRoot)
    x = root2;
  if (isNegativeLE(x, P))
    x = mod(-x, P);
  return { isValid: useRoot1 || useRoot2, value: x };
}
var Fp = /* @__PURE__ */ (() => Field(ed25519_CURVE.p, { isLE: true }))();
var Fn = /* @__PURE__ */ (() => Field(ed25519_CURVE.n, { isLE: true }))();
var ed25519Defaults = /* @__PURE__ */ (() => ({
  ...ed25519_CURVE,
  Fp,
  hash: sha512,
  adjustScalarBytes,
  // dom2
  // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  // Constant-time, u/√v
  uvRatio
}))();
var ed25519 = /* @__PURE__ */ (() => twistedEdwards(ed25519Defaults))();
var SQRT_M1 = ED25519_SQRT_M1;
var SQRT_AD_MINUS_ONE = /* @__PURE__ */ BigInt("25063068953384623474111414158702152701244531502492656460079210482610430750235");
var INVSQRT_A_MINUS_D = /* @__PURE__ */ BigInt("54469307008909316920995813868745141605393597292927456921205312896311721017578");
var ONE_MINUS_D_SQ = /* @__PURE__ */ BigInt("1159843021668779879193775521855586647937357759715417654439879720876111806838");
var D_MINUS_ONE_SQ = /* @__PURE__ */ BigInt("40440834346308536858101042469323190826248399146238708352240133220865137265952");
var invertSqrt = (number) => uvRatio(_1n5, number);
var MAX_255B = /* @__PURE__ */ BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
var bytes255ToNumberLE = (bytes) => ed25519.Point.Fp.create(bytesToNumberLE(bytes) & MAX_255B);
function calcElligatorRistrettoMap(r0) {
  const { d } = ed25519_CURVE;
  const P = ed25519_CURVE_p;
  const mod2 = (n) => Fp.create(n);
  const r = mod2(SQRT_M1 * r0 * r0);
  const Ns = mod2((r + _1n5) * ONE_MINUS_D_SQ);
  let c = BigInt(-1);
  const D = mod2((c - d * r) * mod2(r + d));
  let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D);
  let s_ = mod2(s * r0);
  if (!isNegativeLE(s_, P))
    s_ = mod2(-s_);
  if (!Ns_D_is_sq)
    s = s_;
  if (!Ns_D_is_sq)
    c = r;
  const Nt = mod2(c * (r - _1n5) * D_MINUS_ONE_SQ - D);
  const s2 = s * s;
  const W0 = mod2((s + s) * D);
  const W1 = mod2(Nt * SQRT_AD_MINUS_ONE);
  const W2 = mod2(_1n5 - s2);
  const W3 = mod2(_1n5 + s2);
  return new ed25519.Point(mod2(W0 * W3), mod2(W2 * W1), mod2(W1 * W3), mod2(W0 * W2));
}
function ristretto255_map(bytes) {
  abytes(bytes, 64);
  const r1 = bytes255ToNumberLE(bytes.subarray(0, 32));
  const R1 = calcElligatorRistrettoMap(r1);
  const r2 = bytes255ToNumberLE(bytes.subarray(32, 64));
  const R2 = calcElligatorRistrettoMap(r2);
  return new _RistrettoPoint(R1.add(R2));
}
var _RistrettoPoint = class __RistrettoPoint extends PrimeEdwardsPoint {
  constructor(ep) {
    super(ep);
  }
  static fromAffine(ap) {
    return new __RistrettoPoint(ed25519.Point.fromAffine(ap));
  }
  assertSame(other) {
    if (!(other instanceof __RistrettoPoint))
      throw new Error("RistrettoPoint expected");
  }
  init(ep) {
    return new __RistrettoPoint(ep);
  }
  /** @deprecated use `import { ristretto255_hasher } from '@noble/curves/ed25519.js';` */
  static hashToCurve(hex) {
    return ristretto255_map(ensureBytes("ristrettoHash", hex, 64));
  }
  static fromBytes(bytes) {
    abytes(bytes, 32);
    const { a, d } = ed25519_CURVE;
    const P = ed25519_CURVE_p;
    const mod2 = (n) => Fp.create(n);
    const s = bytes255ToNumberLE(bytes);
    if (!equalBytes(Fp.toBytes(s), bytes) || isNegativeLE(s, P))
      throw new Error("invalid ristretto255 encoding 1");
    const s2 = mod2(s * s);
    const u1 = mod2(_1n5 + a * s2);
    const u2 = mod2(_1n5 - a * s2);
    const u1_2 = mod2(u1 * u1);
    const u2_2 = mod2(u2 * u2);
    const v = mod2(a * d * u1_2 - u2_2);
    const { isValid, value: I } = invertSqrt(mod2(v * u2_2));
    const Dx = mod2(I * u2);
    const Dy = mod2(I * Dx * v);
    let x = mod2((s + s) * Dx);
    if (isNegativeLE(x, P))
      x = mod2(-x);
    const y = mod2(u1 * Dy);
    const t = mod2(x * y);
    if (!isValid || isNegativeLE(t, P) || y === _0n5)
      throw new Error("invalid ristretto255 encoding 2");
    return new __RistrettoPoint(new ed25519.Point(x, y, _1n5, t));
  }
  /**
   * Converts ristretto-encoded string to ristretto point.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-decode).
   * @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
   */
  static fromHex(hex) {
    return __RistrettoPoint.fromBytes(ensureBytes("ristrettoHex", hex, 32));
  }
  static msm(points, scalars) {
    return pippenger(__RistrettoPoint, ed25519.Point.Fn, points, scalars);
  }
  /**
   * Encodes ristretto point to Uint8Array.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-encode).
   */
  toBytes() {
    let { X, Y, Z, T } = this.ep;
    const P = ed25519_CURVE_p;
    const mod2 = (n) => Fp.create(n);
    const u1 = mod2(mod2(Z + Y) * mod2(Z - Y));
    const u2 = mod2(X * Y);
    const u2sq = mod2(u2 * u2);
    const { value: invsqrt } = invertSqrt(mod2(u1 * u2sq));
    const D1 = mod2(invsqrt * u1);
    const D2 = mod2(invsqrt * u2);
    const zInv = mod2(D1 * D2 * T);
    let D;
    if (isNegativeLE(T * zInv, P)) {
      let _x = mod2(Y * SQRT_M1);
      let _y = mod2(X * SQRT_M1);
      X = _x;
      Y = _y;
      D = mod2(D1 * INVSQRT_A_MINUS_D);
    } else {
      D = D2;
    }
    if (isNegativeLE(X * zInv, P))
      Y = mod2(-Y);
    let s = mod2((Z - Y) * D);
    if (isNegativeLE(s, P))
      s = mod2(-s);
    return Fp.toBytes(s);
  }
  /**
   * Compares two Ristretto points.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-equals).
   */
  equals(other) {
    this.assertSame(other);
    const { X: X1, Y: Y1 } = this.ep;
    const { X: X2, Y: Y2 } = other.ep;
    const mod2 = (n) => Fp.create(n);
    const one = mod2(X1 * Y2) === mod2(Y1 * X2);
    const two = mod2(Y1 * Y2) === mod2(X1 * X2);
    return one || two;
  }
  is0() {
    return this.equals(__RistrettoPoint.ZERO);
  }
};
_RistrettoPoint.BASE = /* @__PURE__ */ (() => new _RistrettoPoint(ed25519.Point.BASE))();
_RistrettoPoint.ZERO = /* @__PURE__ */ (() => new _RistrettoPoint(ed25519.Point.ZERO))();
_RistrettoPoint.Fp = /* @__PURE__ */ (() => Fp)();
_RistrettoPoint.Fn = /* @__PURE__ */ (() => Fn)();

// src/types/contracts.ts
var CURRENT_MODEL_VERSION = "0.1";

// src/storage/sharing.ts
var encoder = new TextEncoder();
function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  const output = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    output[i] = binary.charCodeAt(i);
  }
  return output;
}
async function importSecret(secret) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}
async function signSharingPayload(secret, payload) {
  const encodedPayload = encoder.encode(JSON.stringify(payload));
  const key = await importSecret(secret);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encodedPayload));
  return `${toBase64Url(encodedPayload)}.${toBase64Url(signature)}`;
}
async function verifySharingPayload(secret, token, now) {
  const [payloadPart, signaturePart] = token.split(".");
  if (!payloadPart || !signaturePart) {
    throw new Error("invalid sharing token");
  }
  const payloadBytes = fromBase64Url(payloadPart);
  const signatureBytes = fromBase64Url(signaturePart);
  const key = await importSecret(secret);
  const payloadBuffer = payloadBytes.buffer.slice(
    payloadBytes.byteOffset,
    payloadBytes.byteOffset + payloadBytes.byteLength
  );
  const signatureBuffer = signatureBytes.buffer.slice(
    signatureBytes.byteOffset,
    signatureBytes.byteOffset + signatureBytes.byteLength
  );
  const valid = await crypto.subtle.verify("HMAC", key, signatureBuffer, payloadBuffer);
  if (!valid) {
    throw new Error("invalid sharing token");
  }
  const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  if (payload.expiresAt !== void 0 && payload.expiresAt <= now) {
    throw new Error("sharing token expired");
  }
  return payload;
}

// src/auth/capability.ts
var HttpError = class extends Error {
  status;
  code;
  details;
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
};
function getBearerToken(request) {
  const header = request.headers.get("Authorization")?.trim();
  if (!header) {
    throw new HttpError(401, "invalid_capability", "missing Authorization header");
  }
  if (!header.startsWith("Bearer ")) {
    throw new HttpError(401, "invalid_capability", "Authorization header must use Bearer token");
  }
  const token = header.slice("Bearer ".length).trim();
  if (!token) {
    throw new HttpError(401, "invalid_capability", "Bearer token must not be empty");
  }
  return token;
}
async function validateAppendAuthorization(request, deviceId, body, now, sharedState) {
  if (body.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "append request version is not supported");
  }
  if (body.recipientDeviceId !== deviceId || body.envelope.recipientDeviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "recipient device does not match target inbox");
  }
  const authorization = request.headers.get("Authorization")?.trim();
  const capabilityHeader = request.headers.get("X-Tapchat-Capability");
  if (!authorization || !capabilityHeader) {
    return { mode: "legacy_unverified", reason: "missing_append_grant" };
  }
  if (!authorization.startsWith("Bearer ")) {
    return { mode: "legacy_unverified", reason: "invalid_bearer" };
  }
  const signature = authorization.slice("Bearer ".length).trim();
  if (!signature) {
    return { mode: "legacy_unverified", reason: "invalid_bearer" };
  }
  let capability;
  try {
    capability = JSON.parse(capabilityHeader);
  } catch {
    throw new HttpError(400, "invalid_capability", "X-Tapchat-Capability is not valid JSON");
  }
  if (capability.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "append capability version is not supported");
  }
  if (capability.signature !== signature) {
    return { mode: "legacy_unverified", reason: "bearer_mismatch" };
  }
  if (capability.service !== "inbox") {
    throw new HttpError(403, "invalid_capability", "capability service must be inbox");
  }
  if (!capability.operations.includes("append")) {
    throw new HttpError(403, "invalid_capability", "capability does not grant append");
  }
  if (capability.targetDeviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "capability target device does not match request path");
  }
  const requestUrl = new URL(request.url);
  if (capability.endpoint !== `${requestUrl.origin}${requestUrl.pathname}`) {
    throw new HttpError(403, "invalid_capability", "capability endpoint does not match request path");
  }
  if (capability.expiresAt <= now) {
    return { mode: "legacy_unverified", reason: "capability_expired" };
  }
  if (capability.conversationScope?.length && !capability.conversationScope.includes(body.envelope.conversationId)) {
    throw new HttpError(403, "invalid_capability", "conversation is outside capability scope");
  }
  const size = new TextEncoder().encode(JSON.stringify(body.envelope)).byteLength;
  if (capability.constraints?.maxBytes !== void 0 && size > capability.constraints.maxBytes) {
    throw new HttpError(413, "payload_too_large", "envelope exceeds capability size limit");
  }
  const bundle = await sharedState.getIdentityBundle(capability.userId);
  if (!bundle) {
    return { mode: "legacy_unverified", reason: "identity_bundle_missing" };
  }
  if (!verifyIdentityBundle(bundle)) {
    return { mode: "legacy_unverified", reason: "identity_bundle_invalid" };
  }
  if (bundle.userId !== capability.userId) {
    return { mode: "legacy_unverified", reason: "identity_bundle_scope_mismatch" };
  }
  const device = bundle.devices.find((item) => item.deviceId === capability.targetDeviceId);
  if (!device) {
    return { mode: "legacy_unverified", reason: "device_missing" };
  }
  if (device.status !== "active") {
    return { mode: "legacy_unverified", reason: "device_not_active" };
  }
  if (device.deviceId !== capability.targetDeviceId || device.binding.userId !== bundle.userId || device.binding.deviceId !== device.deviceId || device.binding.devicePublicKey !== device.devicePublicKey || device.inboxAppendCapability.signature !== capability.signature) {
    return { mode: "legacy_unverified", reason: "device_binding_mismatch" };
  }
  if (!verifyDeviceBinding(bundle.userPublicKey, device.binding)) {
    return { mode: "legacy_unverified", reason: "device_binding_invalid" };
  }
  if (!verifyInboxAppendCapability(capability, device.devicePublicKey)) {
    return { mode: "legacy_unverified", reason: "capability_signature_invalid" };
  }
  return { mode: "verified" };
}
var APPEND_AUTH_CONTEXT_HEADER = "X-Tapchat-Append-Auth";
var APPEND_AUTH_REASON_HEADER = "X-Tapchat-Append-Auth-Reason";
function capabilityPayload(capability) {
  const constraints = capability.constraints ? `${capability.constraints.maxBytes ?? ""}:${capability.constraints.maxOpsPerMinute ?? ""}` : "";
  return [
    capability.version,
    rustCapabilityServiceDebug(capability.service),
    capability.userId,
    capability.targetDeviceId,
    capability.endpoint,
    rustCapabilityOperationsDebug(capability.operations),
    (capability.conversationScope ?? []).join(","),
    String(capability.expiresAt),
    constraints
  ].join("|");
}
function rustCapabilityServiceDebug(service) {
  return service === "inbox" ? "Inbox" : service;
}
function rustCapabilityOperationsDebug(operations) {
  return `[${operations.map((operation) => operation === "append" ? "Append" : operation).join(", ")}]`;
}
function bindingPayload(binding) {
  return `${CURRENT_MODEL_VERSION}:${binding.userId}:${binding.deviceId}:${binding.devicePublicKey}:${binding.createdAt}`;
}
function identityBundlePayload(bundle, includeDisplayName) {
  const parts = [bundle.version, bundle.userId, bundle.userPublicKey];
  if (includeDisplayName) {
    parts.push(bundle.displayName ?? "");
  }
  parts.push(
    String(bundle.updatedAt),
    bundle.bundleShareId ?? "",
    bundle.identityBundleRef ?? "",
    bundle.deviceStatusRef ?? "",
    bundle.storageProfile?.baseUrl ?? "",
    bundle.storageProfile?.profileRef ?? ""
  );
  for (const device of bundle.devices) {
    parts.push(device.deviceId);
    parts.push(device.devicePublicKey);
    parts.push(device.binding.signature);
    parts.push(device.inboxAppendCapability.signature);
    parts.push(keyPackageRefValue(device));
    parts.push(String(device.keypackageRef.expiresAt));
  }
  return parts.join("|");
}
function keyPackageRefValue(device) {
  const keypackage = device.keypackageRef;
  return keypackage.ref ?? keypackage.objectRef ?? "";
}
function verifyIdentityBundle(bundle) {
  if (bundle.version !== CURRENT_MODEL_VERSION) {
    return false;
  }
  return verifyEd25519(bundle.userPublicKey, bundle.signature, identityBundlePayload(bundle, true)) || verifyEd25519(bundle.userPublicKey, bundle.signature, identityBundlePayload(bundle, false));
}
function verifyDeviceBinding(userPublicKey, binding) {
  if (binding.version !== CURRENT_MODEL_VERSION) {
    return false;
  }
  return verifyEd25519(userPublicKey, binding.signature, bindingPayload(binding));
}
function verifyInboxAppendCapability(capability, devicePublicKey) {
  return verifyEd25519(devicePublicKey, capability.signature, capabilityPayload(capability));
}
function verifyEd25519(publicKeyHex, signatureHex, payload) {
  try {
    const encoded = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
    return ed25519.verify(hexToBytes2(signatureHex), encoded, hexToBytes2(publicKeyHex));
  } catch {
    return false;
  }
}
function groupCapabilitySigningPayload(capability) {
  const operations = Array.from(new Set(capability.operations)).sort().join(",");
  return [
    "tapchat.group_capability.v2",
    `version=${capability.version}`,
    `service=${capability.service}`,
    `group_id=${capability.groupId}`,
    `user_id=${capability.userId}`,
    `device_id=${capability.deviceId}`,
    `role=${capability.role}`,
    `operations=${operations}`,
    `expires_at=${capability.expiresAt}`
  ].join("\n");
}
function unsignedGroupManifest(manifest) {
  return {
    version: manifest.version,
    groupId: manifest.groupId,
    conversationId: manifest.conversationId,
    title: manifest.title,
    ownerUserId: manifest.ownerUserId,
    admins: manifest.admins,
    members: manifest.members.map((member) => ({
      userId: member.userId,
      role: member.role,
      status: member.status
    })),
    ...manifest.memberDevices?.length ? {
      memberDevices: manifest.memberDevices.map((device) => ({
        userId: device.userId,
        deviceId: device.deviceId,
        status: device.status
      }))
    } : {},
    joinPolicy: manifest.joinPolicy,
    memberInvitePolicy: manifest.memberInvitePolicy,
    rosterVersion: manifest.rosterVersion,
    mlsEpochHint: manifest.mlsEpochHint,
    ...manifest.lastCommitMessageId ? { lastCommitMessageId: manifest.lastCommitMessageId } : {},
    outbox: {
      endpoint: manifest.outbox.endpoint,
      ...manifest.outbox.subscribeEndpoint ? { subscribeEndpoint: manifest.outbox.subscribeEndpoint } : {}
    },
    updatedAt: manifest.updatedAt,
    signerUserId: manifest.signerUserId,
    signerDeviceId: manifest.signerDeviceId,
    signature: ""
  };
}
function groupManifestSigningPayload(manifest) {
  const prefix = new TextEncoder().encode("tapchat.group_manifest.v1\n");
  const body = new TextEncoder().encode(JSON.stringify(unsignedGroupManifest(manifest)));
  const payload = new Uint8Array(prefix.length + body.length);
  payload.set(prefix);
  payload.set(body, prefix.length);
  return payload;
}
function groupMembershipProofSigningPayload(proof) {
  const fields = [
    "tapchat.group.membership.v1",
    `proof_type=${proof.type}`,
    `operation=${proof.operation}`,
    `signer_user_id=${proof.signerUserId}`,
    `signer_device_id=${proof.signerDeviceId}`,
    `previous_roster_version=${proof.previousRosterVersion}`,
    `new_roster_version=${proof.newRosterVersion}`,
    `previous_commit_message_id=${proof.previousCommitMessageId ?? ""}`,
    `commit_message_id=${proof.commitMessageId}`,
    `control_message_id=${proof.controlMessageId}`,
    `new_manifest_sha256=${proof.newManifestSha256}`
  ];
  if (proof.stateEventMessageId) {
    fields.push(`state_event_message_id=${proof.stateEventMessageId}`);
  }
  return fields.join("\n");
}
async function groupManifestSha256(manifest) {
  const body = new TextEncoder().encode(JSON.stringify(unsignedGroupManifest(manifest)));
  const digest = await crypto.subtle.digest("SHA-256", body);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function hexToBytes2(input) {
  const value = input.trim();
  if (value.length % 2 !== 0) {
    throw new Error("hex input must have even length");
  }
  if (!/^[0-9a-fA-F]*$/.test(value)) {
    throw new Error("invalid hex input");
  }
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    const byte = Number.parseInt(value.slice(index, index + 2), 16);
    if (!Number.isFinite(byte)) {
      throw new Error("invalid hex input");
    }
    output[index / 2] = byte;
  }
  return output;
}
function readGroupCapabilityHeader(request) {
  const capabilityHeader = request.headers.get("X-Tapchat-Group-Capability");
  if (!capabilityHeader) {
    throw new HttpError(401, "invalid_capability", "missing X-Tapchat-Group-Capability header");
  }
  try {
    return JSON.parse(capabilityHeader);
  } catch {
    throw new HttpError(400, "invalid_capability", "X-Tapchat-Group-Capability is not valid JSON");
  }
}
function validateWelcomePickupAuthorization(request, groupId, deviceId, descriptor, now) {
  const token = getBearerToken(request);
  if (descriptor.groupId !== groupId || descriptor.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "welcome pickup descriptor scope does not match request path");
  }
  const requestUrl = new URL(request.url);
  if (descriptor.endpoint !== `${requestUrl.origin}${requestUrl.pathname}`) {
    throw new HttpError(403, "invalid_capability", "welcome pickup endpoint does not match request path");
  }
  if (descriptor.expiresAt <= now) {
    throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
  }
  if (descriptor.capability !== token) {
    throw new HttpError(403, "invalid_capability", "welcome pickup capability does not match bearer token");
  }
}
function requiredGroupAppendOperations(messageType) {
  switch (messageType) {
    case "mls_application":
      return ["append_application"];
    case "mls_commit":
    case "control_group_membership_changed":
    case "control_group_state_event":
      return ["append_membership"];
    case "control_group_metadata_updated":
      return ["update_group_metadata"];
    case "control_group_join_approved":
    case "control_group_join_rejected":
      return ["approve_join"];
    case "control_group_leave_requested":
    case "control_group_join_requested":
    case "control_conversation_needs_rebuild":
      return ["append_control"];
    default:
      return ["append_control"];
  }
}
function allowedGroupAppendRoles(messageType) {
  switch (messageType) {
    case "mls_commit":
    case "control_group_membership_changed":
    case "control_group_state_event":
    case "control_group_metadata_updated":
    case "control_group_join_approved":
    case "control_group_join_rejected":
      return ["owner", "admin"];
    default:
      return ["owner", "admin", "member"];
  }
}
function tokenKeyId(token) {
  try {
    const payloadPart = token.split(".")[0];
    if (!payloadPart) return void 0;
    const normalized = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const payload = JSON.parse(atob(padded));
    return typeof payload.keyId === "string" && payload.keyId.trim() ? payload.keyId : void 0;
  } catch {
    return void 0;
  }
}
async function verifySignedToken(secrets, request, now) {
  const token = getBearerToken(request);
  const candidates = typeof secrets === "string" ? [secrets] : (() => {
    const keyId = tokenKeyId(token);
    if (keyId) {
      if (keyId === secrets.current.keyId) return [secrets.current.secret];
      if (secrets.previous?.keyId === keyId && secrets.graceUntilMs !== void 0 && now < secrets.graceUntilMs) return [secrets.previous.secret];
      return [];
    }
    return secrets.allowUnkeyedCurrent ? [secrets.current.secret] : [];
  })();
  let lastMessage = "invalid signed token";
  for (const secret of candidates) {
    try {
      return await verifySharingPayload(secret, token, now);
    } catch (error) {
      lastMessage = error instanceof Error ? error.message : lastMessage;
    }
  }
  if (lastMessage.includes("expired")) {
    throw new HttpError(403, "capability_expired", lastMessage);
  }
  throw new HttpError(403, "invalid_capability", lastMessage);
}
async function verifyDeviceRuntimeToken(request, secrets, now) {
  let token;
  try {
    token = await verifySignedToken(secrets, request, now);
  } catch (error) {
    if (error instanceof HttpError && error.code === "capability_expired") {
      throw new HttpError(403, "runtime_auth_expired", "device runtime token is expired");
    }
    throw new HttpError(403, "runtime_auth_invalid", "device runtime token is invalid");
  }
  if (token.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "device runtime token version is not supported");
  }
  if (token.service !== "device_runtime") {
    throw new HttpError(403, "runtime_auth_invalid", "token service must be device_runtime");
  }
  if (!token.runtimeId || !token.userId || !token.deviceId || !token.scopes.length || !Number.isSafeInteger(token.issuedAt) || !Number.isSafeInteger(token.registrationVersion) || token.registrationVersion < 1) {
    throw new HttpError(403, "runtime_auth_invalid", "device runtime token is malformed");
  }
  return token;
}
async function validateAnyDeviceRuntimeAuthorization(request, secret, scope, now) {
  const token = await verifyDeviceRuntimeToken(request, secret, now);
  if (!token.scopes.includes(scope)) {
    throw new HttpError(403, "runtime_auth_invalid", `device runtime token does not grant ${scope}`);
  }
  return token;
}
async function validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, scope, now) {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.userId !== userId || token.deviceId !== deviceId) {
    throw new HttpError(403, "runtime_auth_invalid", "device runtime token scope does not match request path");
  }
  return token;
}
async function validateDeviceRuntimeAuthorizationForDevice(request, secret, deviceId, scope, now) {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.deviceId !== deviceId) {
    throw new HttpError(403, "runtime_auth_invalid", "device runtime token scope does not match request path");
  }
  return token;
}
async function validateSharedStateWriteAuthorization(request, secret, userId, deviceId, objectKind, now) {
  try {
    return await validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, "shared_state_write", now);
  } catch (error) {
    if (!(error instanceof HttpError) || error.code === "runtime_auth_expired") {
      throw error;
    }
  }
  const token = await verifySignedToken(secret, request, now);
  if (token.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "shared-state token version is not supported");
  }
  if (token.service !== "shared_state") {
    throw new HttpError(403, "invalid_capability", "token service must be shared_state");
  }
  if (token.userId !== userId) {
    throw new HttpError(403, "invalid_capability", "token userId does not match request path");
  }
  if (!token.objectKinds.includes(objectKind)) {
    throw new HttpError(403, "invalid_capability", "token does not grant this shared-state object kind");
  }
  return token;
}
async function validateKeyPackageWriteAuthorization(request, secret, userId, deviceId, keyPackageId, now, legacySecret) {
  try {
    return await validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, "keypackage_write", now);
  } catch (error) {
    if (!(error instanceof HttpError) || error.code === "runtime_auth_expired") {
      throw error;
    }
  }
  const token = await verifySignedToken(legacySecret ?? secret, request, now);
  if (token.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "keypackage token version is not supported");
  }
  if (token.service !== "keypackages") {
    throw new HttpError(403, "invalid_capability", "token service must be keypackages");
  }
  if (token.userId !== userId || token.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "token scope does not match request path");
  }
  if (token.keyPackageId && token.keyPackageId !== keyPackageId) {
    throw new HttpError(403, "invalid_capability", "token keyPackageId does not match request path");
  }
  return token;
}

// src/auth/runtime-security.ts
var CONTROL_JSON_MAX_BYTES = 64 * 1024;
var DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES = 320 * 1024;
var MIN_SECRET_BYTES = 32;
var PLACEHOLDER_SECRETS = /* @__PURE__ */ new Set([
  "replace-me",
  "replace-me-bootstrap",
  "changeme",
  "change-me",
  "secret"
]);
function requireSecretValue(value, label) {
  const secret = value?.trim();
  if (!secret || new TextEncoder().encode(secret).byteLength < MIN_SECRET_BYTES || PLACEHOLDER_SECRETS.has(secret.toLowerCase())) {
    throw new HttpError(
      503,
      "runtime_misconfigured",
      `${label} is missing or invalid`
    );
  }
  return secret;
}
function requireSharingSecret(env) {
  return requireSecretValue(env.SHARING_INTERNAL_SECRET, "SHARING_INTERNAL_SECRET");
}
function optionalKeyId(value) {
  const keyId = value?.trim();
  return keyId || void 0;
}
function rotationGraceUntilMs(env) {
  const raw = env.AUTH_ROTATION_GRACE_UNTIL_MS?.trim();
  if (!raw) return void 0;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new HttpError(503, "runtime_misconfigured", "AUTH_ROTATION_GRACE_UNTIL_MS is invalid");
  }
  return value;
}
function requireDeviceRuntimeSecrets(env) {
  const currentKeyId = optionalKeyId(env.DEVICE_RUNTIME_SECRET_KEY_ID);
  if (!currentKeyId) {
    throw new HttpError(503, "runtime_misconfigured", "DEVICE_RUNTIME_SECRET_KEY_ID is missing");
  }
  const previousSecret = env.DEVICE_RUNTIME_SECRET_PREVIOUS?.trim();
  return {
    current: {
      secret: requireSecretValue(env.DEVICE_RUNTIME_SECRET, "DEVICE_RUNTIME_SECRET"),
      keyId: currentKeyId
    },
    previous: previousSecret ? {
      secret: requireSecretValue(previousSecret, "DEVICE_RUNTIME_SECRET_PREVIOUS"),
      keyId: optionalKeyId(env.DEVICE_RUNTIME_SECRET_PREVIOUS_KEY_ID)
    } : void 0,
    graceUntilMs: rotationGraceUntilMs(env),
    allowUnkeyedCurrent: false
  };
}
async function readRequestTextLimited(request, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new HttpError(500, "runtime_misconfigured", "request body limit is invalid");
  }
  const declaredLength = request.headers.get("Content-Length");
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (!Number.isFinite(parsed) || parsed < 0) {
      throw new HttpError(400, "invalid_input", "Content-Length is invalid");
    }
    if (parsed > maxBytes) {
      throw new HttpError(413, "request_too_large", "request body exceeds the configured limit");
    }
  }
  if (!request.body) {
    return "";
  }
  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let byteLength = 0;
  let body = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      byteLength += value.byteLength;
      if (byteLength > maxBytes) {
        await reader.cancel("request body exceeds configured limit");
        throw new HttpError(413, "request_too_large", "request body exceeds the configured limit");
      }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
    return body;
  } finally {
    reader.releaseLock();
  }
}
async function readJsonLimited(request, maxBytes) {
  const body = await readRequestTextLimited(request, maxBytes);
  try {
    return JSON.parse(body);
  } catch {
    throw new HttpError(400, "invalid_input", "request body is not valid JSON");
  }
}

// src/auth/runtime-auth.ts
function deviceRuntimeSigningPayload(challenge) {
  return [
    "tapchat.device_runtime_auth.v2",
    `purpose=${challenge.purpose}`,
    `runtime_id=${challenge.runtimeId}`,
    `user_id=${challenge.userId}`,
    `device_id=${challenge.deviceId}`,
    `nonce=${challenge.nonce}`,
    `expires_at=${challenge.expiresAt}`
  ].join("\n");
}

// src/device-registry/durable.ts
var CHALLENGE_TTL_MS = 5 * 60 * 1e3;
var CHALLENGE_PREFIX = "challenge:";
var DEVICE_PREFIX = "device:";
var MAX_ACTIVE_CHALLENGES = 8;
var DurableObjectBase = globalThis.DurableObject ?? class {
  constructor(_state, _env) {
  }
};
function jsonResponse(body, status = 200) {
  return Response.json(body, { status });
}
function runtimeConfig(env) {
  const runtimeId = env.RUNTIME_ID?.trim();
  const userId = env.OWNER_USER_ID?.trim();
  const userPublicKey = env.OWNER_USER_PUBLIC_KEY?.trim();
  if (!runtimeId || !userId || !userPublicKey) {
    throw new HttpError(503, "runtime_misconfigured", "runtime owner identity is not configured");
  }
  return { runtimeId, userId, userPublicKey };
}
function challengeKey(nonce) {
  return `${CHALLENGE_PREFIX}${nonce}`;
}
function deviceKey(deviceId) {
  return `${DEVICE_PREFIX}${deviceId}`;
}
function randomNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function bindingHash(device) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(device.binding))
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function assertChallengeScope(challenge, purpose, config, now) {
  if (challenge.version !== CURRENT_MODEL_VERSION || challenge.purpose !== purpose || challenge.runtimeId !== config.runtimeId || challenge.userId !== config.userId || !challenge.deviceId || !challenge.nonce || challenge.expiresAt <= now) {
    throw new HttpError(403, "runtime_auth_invalid", "runtime authorization challenge is invalid or expired");
  }
}
function sameChallenge(stored, submitted) {
  return stored.version === submitted.version && stored.purpose === submitted.purpose && stored.runtimeId === submitted.runtimeId && stored.userId === submitted.userId && stored.deviceId === submitted.deviceId && stored.nonce === submitted.nonce && stored.expiresAt === submitted.expiresAt;
}
var DeviceRegistryDurableObject = class extends DurableObjectBase {
  stateRef;
  envRef;
  constructor(state, env) {
    super(state, env);
    this.stateRef = state;
    this.envRef = env;
  }
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const now = Date.now();
      if (request.method === "GET" && url.pathname.endsWith("/ready")) {
        return await this.ready();
      }
      if (request.method === "POST" && url.pathname.endsWith("/challenge")) {
        return await this.issueChallenge(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/enroll")) {
        return await this.enroll(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/refresh")) {
        return await this.refresh(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/authorize")) {
        return await this.authorize(request);
      }
      if (request.method === "POST" && url.pathname.endsWith("/sync")) {
        return await this.syncIdentityBundle(request, now);
      }
      return jsonResponse({ error: "not_found" }, 404);
    } catch (error) {
      if (error instanceof HttpError) {
        return jsonResponse({ error: error.code, message: error.message }, error.status);
      }
      return jsonResponse({ error: "temporary_unavailable", message: "device registry request failed" }, 500);
    }
  }
  async ready() {
    const config = runtimeConfig(this.envRef);
    await this.stateRef.storage.get("__runtime_registry_ready__");
    return jsonResponse({
      ready: true,
      runtimeId: config.runtimeId,
      protocolVersion: 4,
      workerBuildId: this.envRef.WORKER_BUILD_ID?.trim() || "tapchat-worker-v4-unknown",
      registrySchemaVersion: 1
    });
  }
  async issueChallenge(request, now) {
    const config = runtimeConfig(this.envRef);
    const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
    if (body.purpose !== "enroll" && body.purpose !== "refresh" || body.userId !== config.userId || !body.deviceId) {
      throw new HttpError(400, "runtime_auth_invalid", "runtime authorization challenge scope is invalid");
    }
    if (body.purpose === "refresh") {
      const record = await this.stateRef.storage.get(deviceKey(body.deviceId));
      if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
      if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    }
    const existing = await this.stateRef.storage.list({ prefix: CHALLENGE_PREFIX });
    const expired = Array.from(existing.entries()).filter(([, challenge2]) => challenge2.expiresAt <= now).map(([key]) => key);
    if (expired.length) await this.stateRef.storage.delete(expired);
    if (existing.size - expired.length >= MAX_ACTIVE_CHALLENGES) {
      throw new HttpError(429, "rate_limited", "too many active runtime authorization challenges");
    }
    const challenge = {
      version: CURRENT_MODEL_VERSION,
      purpose: body.purpose,
      runtimeId: config.runtimeId,
      userId: config.userId,
      deviceId: body.deviceId,
      nonce: randomNonce(),
      expiresAt: now + CHALLENGE_TTL_MS
    };
    await this.stateRef.storage.put(challengeKey(challenge.nonce), challenge);
    return jsonResponse(challenge);
  }
  async consumeChallenge(challenge, purpose, now) {
    const config = runtimeConfig(this.envRef);
    assertChallengeScope(challenge, purpose, config, now);
    const key = challengeKey(challenge.nonce);
    const consumed = await this.stateRef.storage.transaction(async (transaction) => {
      const stored = await transaction.get(key);
      if (!stored || !sameChallenge(stored, challenge)) return false;
      await transaction.delete(key);
      return true;
    });
    if (!consumed) {
      throw new HttpError(403, "challenge_replayed", "runtime authorization challenge was already consumed");
    }
  }
  async enroll(request, now) {
    const config = runtimeConfig(this.envRef);
    const proof = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
    const { challenge, device } = proof;
    assertChallengeScope(challenge, "enroll", config, now);
    if (!device || device.status !== "active" || device.deviceId !== challenge.deviceId || device.devicePublicKey !== device.binding.devicePublicKey || device.binding.userId !== config.userId || device.binding.deviceId !== device.deviceId || !verifyDeviceBinding(config.userPublicKey, device.binding) || !verifyEd25519(device.devicePublicKey, proof.signature, deviceRuntimeSigningPayload(challenge))) {
      throw new HttpError(403, "runtime_auth_invalid", "device enrollment proof is invalid");
    }
    const key = deviceKey(device.deviceId);
    const hash = await bindingHash(device);
    const existing = await this.stateRef.storage.get(key);
    if (existing?.status === "revoked") {
      throw new HttpError(403, "device_revoked", "revoked devices cannot be re-enrolled");
    }
    if (existing && (existing.devicePublicKey !== device.devicePublicKey || existing.bindingHash !== hash)) {
      throw new HttpError(403, "runtime_auth_invalid", "registered device identity does not match");
    }
    await this.consumeChallenge(challenge, "enroll", now);
    const record = existing ?? {
      version: CURRENT_MODEL_VERSION,
      runtimeId: config.runtimeId,
      userId: config.userId,
      deviceId: device.deviceId,
      devicePublicKey: device.devicePublicKey,
      bindingHash: hash,
      status: "active",
      registrationVersion: 1,
      createdAt: now,
      updatedAt: now
    };
    await this.stateRef.storage.put(key, { ...record, updatedAt: now });
    return jsonResponse({ registrationVersion: record.registrationVersion });
  }
  async refresh(request, now) {
    const proof = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
    const config = runtimeConfig(this.envRef);
    assertChallengeScope(proof.challenge, "refresh", config, now);
    const record = await this.stateRef.storage.get(deviceKey(proof.challenge.deviceId));
    if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
    if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    if (!verifyEd25519(record.devicePublicKey, proof.signature, deviceRuntimeSigningPayload(proof.challenge))) {
      throw new HttpError(403, "runtime_auth_invalid", "runtime authorization proof is invalid");
    }
    await this.consumeChallenge(proof.challenge, "refresh", now);
    return jsonResponse({ registrationVersion: record.registrationVersion });
  }
  async authorize(request) {
    const token = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
    const config = runtimeConfig(this.envRef);
    if (token.runtimeId !== config.runtimeId || token.userId !== config.userId) {
      throw new HttpError(403, "runtime_mismatch", "runtime token audience does not match this runtime");
    }
    const record = await this.stateRef.storage.get(deviceKey(token.deviceId));
    if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
    if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    if (record.registrationVersion !== token.registrationVersion) {
      throw new HttpError(403, "runtime_auth_invalid", "runtime token registration is stale");
    }
    return jsonResponse({ active: true });
  }
  async syncIdentityBundle(request, now) {
    const bundle = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
    const config = runtimeConfig(this.envRef);
    if (bundle.userId !== config.userId || bundle.userPublicKey !== config.userPublicKey || !verifyIdentityBundle(bundle)) {
      throw new HttpError(403, "runtime_auth_invalid", "identity bundle does not match runtime owner");
    }
    const changes = [];
    for (const device of bundle.devices) {
      if (device.binding.userId !== config.userId || device.binding.deviceId !== device.deviceId || device.binding.devicePublicKey !== device.devicePublicKey || !verifyDeviceBinding(config.userPublicKey, device.binding)) {
        throw new HttpError(403, "runtime_auth_invalid", "identity bundle contains an invalid device binding");
      }
      const key = deviceKey(device.deviceId);
      const hash = await bindingHash(device);
      const existing = await this.stateRef.storage.get(key);
      if (existing && (existing.devicePublicKey !== device.devicePublicKey || existing.bindingHash !== hash)) {
        throw new HttpError(403, "runtime_auth_invalid", "identity bundle attempts to replace a registered device key");
      }
      if (existing?.status === "revoked" && device.status === "active") {
        throw new HttpError(403, "device_revoked", "identity bundle attempts to reactivate a revoked device");
      }
      const status = existing?.status === "revoked" || device.status === "revoked" ? "revoked" : "active";
      changes.push({
        key,
        record: {
          version: CURRENT_MODEL_VERSION,
          runtimeId: config.runtimeId,
          userId: config.userId,
          deviceId: device.deviceId,
          devicePublicKey: device.devicePublicKey,
          bindingHash: hash,
          status,
          registrationVersion: existing && existing.status !== status ? existing.registrationVersion + 1 : existing?.registrationVersion ?? 1,
          createdAt: existing?.createdAt ?? now,
          updatedAt: now
        }
      });
    }
    await this.stateRef.storage.transaction(async (transaction) => {
      for (const change of changes) await transaction.put(change.key, change.record);
    });
    return jsonResponse({ synchronized: changes.length });
  }
};
function registryStub(env) {
  const runtimeId = runtimeConfig(env).runtimeId;
  return env.DEVICE_REGISTRY.get(env.DEVICE_REGISTRY.idFromName(runtimeId));
}
async function assertRegisteredRuntimeToken(env, token) {
  const response = await registryStub(env).fetch(
    new Request("https://device-registry.internal/v2/device-registry/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(token)
    })
  );
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new HttpError(response.status, body.error ?? "runtime_auth_invalid", body.message ?? "device registry rejected token");
  }
}

// src/group-outbox/authorization.ts
var GROUP_AUTHORIZATION_KEY = "group-authorization:v2";
var MAX_CAPABILITY_TTL_MS = 24 * 60 * 60 * 1e3 + 5 * 60 * 1e3;
var ROLE_OPERATIONS = {
  owner: /* @__PURE__ */ new Set([
    "read",
    "subscribe",
    "append_application",
    "append_control",
    "append_membership",
    "manage_invites",
    "approve_join",
    "remove_member",
    "update_group_metadata",
    "seal_group"
  ]),
  admin: /* @__PURE__ */ new Set([
    "read",
    "subscribe",
    "append_application",
    "append_control",
    "append_membership",
    "manage_invites",
    "approve_join",
    "remove_member",
    "update_group_metadata"
  ]),
  member: /* @__PURE__ */ new Set(["read", "subscribe", "append_application", "append_control"])
};
function deviceKey2(userId, deviceId) {
  return `${userId}\0${deviceId}`;
}
function activeMember(manifest, userId) {
  return manifest.members.find((member) => member.userId === userId && member.status === "active");
}
function canonicalJson(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalJson);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, canonicalJson(item)])
    );
  }
  return value;
}
function sameJson(left, right) {
  return JSON.stringify(canonicalJson(left)) === JSON.stringify(canonicalJson(right));
}
function validateManifestShape(manifest, groupId) {
  if (manifest.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "group manifest version is not supported");
  }
  if (manifest.groupId !== groupId || !manifest.conversationId || !manifest.signature) {
    throw new HttpError(400, "group_transition_invalid", "group manifest scope or signature is invalid");
  }
  if (!Number.isSafeInteger(manifest.rosterVersion) || manifest.rosterVersion < 0) {
    throw new HttpError(400, "group_transition_invalid", "group manifest rosterVersion is invalid");
  }
  const activeOwners = manifest.members.filter(
    (member) => member.status === "active" && member.role === "owner"
  );
  if (activeOwners.length !== 1 || activeOwners[0].userId !== manifest.ownerUserId) {
    throw new HttpError(409, "group_transition_invalid", "group manifest must contain exactly one active owner");
  }
  const memberIds = /* @__PURE__ */ new Set();
  for (const member of manifest.members) {
    if (!member.userId || memberIds.has(member.userId)) {
      throw new HttpError(409, "group_transition_invalid", "group manifest contains duplicate or empty members");
    }
    memberIds.add(member.userId);
  }
  const activeAdminIds = manifest.members.filter((member) => member.status === "active" && member.role === "admin").map((member) => member.userId).sort();
  if (!sameJson(Array.from(new Set(manifest.admins)).sort(), activeAdminIds)) {
    throw new HttpError(409, "group_transition_invalid", "group manifest admin index does not match active member roles");
  }
  if (manifest.rosterVersion === 0) {
    const ownerOnly = manifest.members.length === 1 && manifest.members[0].userId === manifest.ownerUserId && manifest.members[0].role === "owner" && manifest.members[0].status === "active";
    if (!ownerOnly || manifest.admins.length !== 0 || manifest.mlsEpochHint !== 0 || manifest.lastCommitMessageId) {
      throw new HttpError(409, "group_transition_invalid", "provisional group manifest must be owner-only at roster 0 and MLS epoch 0");
    }
  }
  const memberDeviceIds = /* @__PURE__ */ new Set();
  for (const device of manifest.memberDevices ?? []) {
    if (!memberIds.has(device.userId) || !device.deviceId || memberDeviceIds.has(device.deviceId)) {
      throw new HttpError(409, "group_transition_invalid", "group manifest contains an invalid member device");
    }
    memberDeviceIds.add(device.deviceId);
  }
  let endpoint;
  try {
    endpoint = new URL(manifest.outbox.endpoint);
  } catch {
    throw new HttpError(409, "group_transition_invalid", "group outbox endpoint is invalid");
  }
  const match = endpoint.pathname.match(/^\/v1\/groups\/([^/]+)\/outbox\/messages$/);
  if (!match || decodeURIComponent(match[1]) !== groupId) {
    throw new HttpError(409, "group_transition_invalid", "group outbox endpoint does not match groupId");
  }
}
function mergeVerifiedDevices(existing, bundles) {
  const devices = { ...existing };
  for (const bundle of bundles) {
    if (!verifyIdentityBundle(bundle)) {
      throw new HttpError(403, "invalid_capability", `identity bundle is invalid for ${bundle.userId}`);
    }
    for (const device of bundle.devices) {
      if (device.binding.userId !== bundle.userId || device.binding.deviceId !== device.deviceId || device.binding.devicePublicKey !== device.devicePublicKey || !verifyDeviceBinding(bundle.userPublicKey, device.binding)) {
        throw new HttpError(403, "invalid_capability", `device binding is invalid for ${device.deviceId}`);
      }
      devices[deviceKey2(bundle.userId, device.deviceId)] = {
        userId: bundle.userId,
        deviceId: device.deviceId,
        publicKey: device.devicePublicKey,
        status: device.status
      };
    }
  }
  return devices;
}
function validateManifestDevices(manifest, devices) {
  for (const memberDevice of manifest.memberDevices ?? []) {
    if (memberDevice.status !== "active") {
      continue;
    }
    const device = devices[deviceKey2(memberDevice.userId, memberDevice.deviceId)];
    if (!device || device.status !== "active" || device.userId !== memberDevice.userId) {
      throw new HttpError(
        409,
        "group_transition_invalid",
        `active manifest device has no verified identity binding: ${memberDevice.deviceId}`
      );
    }
  }
}
function verifyManifestSignature(manifest, devices) {
  const signer = devices[deviceKey2(manifest.signerUserId, manifest.signerDeviceId)];
  const signerMember = activeMember(manifest, manifest.signerUserId);
  const signerDevice = (manifest.memberDevices ?? []).find(
    (device) => device.userId === manifest.signerUserId && device.deviceId === manifest.signerDeviceId && device.status === "active"
  );
  if (!signer || signer.status !== "active" || !signerDevice || !signerMember || !["owner", "admin"].includes(signerMember.role) || !verifyEd25519(signer.publicKey, manifest.signature, groupManifestSigningPayload(manifest))) {
    throw new HttpError(403, "invalid_capability", "group manifest signature is invalid");
  }
}
function verifyMembershipProof(proof, oldState, nextManifest) {
  const signer = oldState.devices[deviceKey2(proof.signerUserId, proof.signerDeviceId)];
  const signerMember = activeMember(oldState.manifest, proof.signerUserId);
  if (proof.type !== "membership_signature" || !signer || signer.status !== "active" || !signerMember || !["owner", "admin"].includes(signerMember.role) || !verifyEd25519(signer.publicKey, proof.signature, groupMembershipProofSigningPayload(proof))) {
    throw new HttpError(403, "invalid_capability", "group membership proof signature is invalid");
  }
  if (proof.previousRosterVersion !== oldState.manifest.rosterVersion || proof.newRosterVersion !== nextManifest.rosterVersion) {
    throw new HttpError(409, "group_transition_invalid", "group membership proof roster chain is invalid");
  }
  if ((proof.previousCommitMessageId ?? "") !== (oldState.manifest.lastCommitMessageId ?? "")) {
    throw new HttpError(409, "group_transition_invalid", "group membership proof commit chain is invalid");
  }
  if (["create", "transfer_ownership", "set_admin", "dissolve"].includes(proof.operation) && signerMember.role !== "owner") {
    throw new HttpError(403, "invalid_capability", `${proof.operation} requires the current group owner`);
  }
}
function verifyIdempotentMembershipProof(proof, current, manifestHash) {
  if (current.lastTransitionProof && sameJson(current.lastTransitionProof, proof)) {
    return;
  }
  const signer = current.devices[deviceKey2(proof.signerUserId, proof.signerDeviceId)];
  const signerMember = activeMember(current.manifest, proof.signerUserId);
  if (proof.type !== "membership_signature" || !signer || signer.status !== "active" || !signerMember || !["owner", "admin"].includes(signerMember.role) || !verifyEd25519(signer.publicKey, proof.signature, groupMembershipProofSigningPayload(proof))) {
    throw new HttpError(403, "invalid_capability", "group membership proof signature is invalid");
  }
  if (proof.newRosterVersion !== current.manifest.rosterVersion || proof.newManifestSha256 !== manifestHash) {
    throw new HttpError(409, "group_transition_invalid", "idempotent group transition does not match current manifest");
  }
  if (["transfer_ownership", "set_admin", "dissolve"].includes(proof.operation) && signerMember.role !== "owner") {
    throw new HttpError(403, "invalid_capability", `${proof.operation} requires the current group owner`);
  }
}
function manifestTransitionMatches(oldManifest, nextManifest, applyAllowedChanges) {
  const expected = JSON.parse(JSON.stringify(oldManifest));
  expected.rosterVersion = nextManifest.rosterVersion;
  expected.mlsEpochHint = nextManifest.mlsEpochHint;
  expected.updatedAt = nextManifest.updatedAt;
  expected.signerUserId = nextManifest.signerUserId;
  expected.signerDeviceId = nextManifest.signerDeviceId;
  expected.signature = nextManifest.signature;
  applyAllowedChanges(expected);
  return sameJson(expected, nextManifest);
}
function membershipAdditionsAreWellFormed(oldManifest, nextManifest) {
  if (nextManifest.members.length <= oldManifest.members.length) {
    return false;
  }
  const oldMembers = new Map(oldManifest.members.map((member) => [member.userId, member]));
  let added = 0;
  for (const member of nextManifest.members) {
    const oldMember = oldMembers.get(member.userId);
    if (oldMember) {
      if (!sameJson(oldMember, member)) {
        return false;
      }
    } else if (member.role === "member" && member.status === "active") {
      added += 1;
    } else {
      return false;
    }
  }
  return added > 0;
}
function genesisTransitionIsWellFormed(oldManifest, nextManifest) {
  const oldMembers = new Map(oldManifest.members.map((member) => [member.userId, member]));
  for (const member of nextManifest.members) {
    const old = oldMembers.get(member.userId);
    if (old ? !sameJson(old, member) : member.role !== "member" || member.status !== "active") return false;
  }
  if (oldManifest.members.some((member) => !nextManifest.members.some((next) => sameJson(member, next)))) return false;
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (oldDevices.some((device) => !nextDevices.some((next) => sameJson(device, next)))) return false;
  return nextDevices.every(
    (device) => oldDevices.some((old) => sameJson(old, device)) || device.status === "active" && nextManifest.members.some((member) => member.userId === device.userId && member.status === "active")
  );
}
function membershipDeviceAdditionsAreWellFormed(oldManifest, nextManifest, addedUserIds) {
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (oldDevices.some((device) => !nextDevices.some((next) => sameJson(device, next)))) return false;
  return nextDevices.every(
    (device) => oldDevices.some((old) => sameJson(old, device)) || addedUserIds.has(device.userId) && device.status === "active"
  );
}
function memberRemovalIsWellFormed(oldManifest, nextManifest, nextStatus) {
  if (oldManifest.members.length !== nextManifest.members.length) {
    return false;
  }
  let removals = 0;
  for (const oldMember of oldManifest.members) {
    const nextMember = nextManifest.members.find((member) => member.userId === oldMember.userId);
    if (!nextMember) {
      return false;
    }
    if (sameJson(oldMember, nextMember)) {
      continue;
    }
    if (oldMember.role === nextMember.role && oldMember.status === "active" && nextMember.status === nextStatus && oldMember.role !== "owner") {
      removals += 1;
      continue;
    }
    return false;
  }
  return removals === 1;
}
function deviceAdditionIsWellFormed(oldManifest, nextManifest) {
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (!sameJson(oldManifest.members, nextManifest.members) || nextDevices.length !== oldDevices.length + 1) {
    return false;
  }
  let added = 0;
  for (const device of nextDevices) {
    if (oldDevices.some((oldDevice) => sameJson(oldDevice, device))) {
      continue;
    }
    if (device.status !== "active" || !oldManifest.members.some((member) => member.userId === device.userId && member.status === "active")) {
      return false;
    }
    added += 1;
  }
  return added === 1;
}
function deviceRemovalIsWellFormed(oldManifest, nextManifest) {
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (!sameJson(oldManifest.members, nextManifest.members) || oldDevices.length !== nextDevices.length) {
    return false;
  }
  let removals = 0;
  for (const oldDevice of oldDevices) {
    const nextDevice = nextDevices.find((device) => device.deviceId === oldDevice.deviceId);
    if (!nextDevice) {
      return false;
    }
    if (sameJson(oldDevice, nextDevice)) {
      continue;
    }
    if (oldDevice.userId === nextDevice.userId && oldDevice.status === "active" && nextDevice.status === "removed" && oldDevice.userId !== oldManifest.ownerUserId) {
      removals += 1;
      continue;
    }
    return false;
  }
  return removals === 1;
}
function memberDevicesForRemovalAreWellFormed(oldManifest, nextManifest, userId) {
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (oldDevices.length !== nextDevices.length) return false;
  for (const oldDevice of oldDevices) {
    const nextDevice = nextDevices.find(
      (device) => device.userId === oldDevice.userId && device.deviceId === oldDevice.deviceId
    );
    if (!nextDevice) return false;
    if (oldDevice.userId !== userId) {
      if (!sameJson(oldDevice, nextDevice)) return false;
    } else if (oldDevice.status === "active" && nextDevice.status !== "removed") {
      return false;
    }
  }
  return true;
}
function adminUpdateIsWellFormed(oldManifest, nextManifest) {
  if (oldManifest.members.length !== nextManifest.members.length) {
    return false;
  }
  let roleChanges = 0;
  for (const oldMember of oldManifest.members) {
    const nextMember = nextManifest.members.find((member) => member.userId === oldMember.userId);
    if (!nextMember) {
      return false;
    }
    if (sameJson(oldMember, nextMember)) {
      continue;
    }
    if (oldMember.status === "active" && nextMember.status === "active" && oldMember.role !== "owner" && (oldMember.role === "member" && nextMember.role === "admin" || oldMember.role === "admin" && nextMember.role === "member")) {
      roleChanges += 1;
      continue;
    }
    return false;
  }
  return roleChanges === 1;
}
function ownershipTransferIsWellFormed(oldManifest, nextManifest) {
  if (oldManifest.ownerUserId === nextManifest.ownerUserId || oldManifest.members.length !== nextManifest.members.length) {
    return false;
  }
  let oldOwnerChanged = false;
  let newOwnerChanged = false;
  for (const oldMember of oldManifest.members) {
    const nextMember = nextManifest.members.find((member) => member.userId === oldMember.userId);
    if (!nextMember) {
      return false;
    }
    if (sameJson(oldMember, nextMember)) {
      continue;
    }
    if (oldMember.userId === oldManifest.ownerUserId && oldMember.role === "owner" && nextMember.role === "admin" && oldMember.status === "active" && nextMember.status === "active") {
      oldOwnerChanged = true;
      continue;
    }
    if (oldMember.userId === nextManifest.ownerUserId && oldMember.role !== "owner" && nextMember.role === "owner" && oldMember.status === "active" && nextMember.status === "active") {
      newOwnerChanged = true;
      continue;
    }
    return false;
  }
  return oldOwnerChanged && newOwnerChanged;
}
function dissolveTransitionIsWellFormed(oldManifest, nextManifest) {
  if (oldManifest.members.length !== nextManifest.members.length) {
    return false;
  }
  let removedCount = 0;
  for (const oldMember of oldManifest.members) {
    const nextMember = nextManifest.members.find((member) => member.userId === oldMember.userId);
    if (!nextMember) {
      return false;
    }
    if (oldMember.userId === oldManifest.ownerUserId) {
      if (!sameJson(oldMember, nextMember)) {
        return false;
      }
      continue;
    }
    if (oldMember.status === "active" && nextMember.status === "removed" && oldMember.role === nextMember.role) {
      removedCount += 1;
      continue;
    }
    if (!sameJson(oldMember, nextMember)) {
      return false;
    }
  }
  return removedCount > 0 || oldManifest.members.length === 1;
}
function validateTransitionShape(oldManifest, nextManifest, proof, operation) {
  if (oldManifest.groupId !== nextManifest.groupId || oldManifest.conversationId !== nextManifest.conversationId || !sameJson(oldManifest.outbox, nextManifest.outbox) || nextManifest.rosterVersion !== oldManifest.rosterVersion + 1) {
    throw new HttpError(409, "group_transition_invalid", "group manifest transition is not contiguous");
  }
  if (proof.signerUserId !== nextManifest.signerUserId || proof.signerDeviceId !== nextManifest.signerDeviceId) {
    throw new HttpError(409, "group_transition_invalid", "group transition signer does not match the manifest signer");
  }
  const commitChanged = proof.commitMessageId !== (proof.previousCommitMessageId ?? "");
  if ((nextManifest.lastCommitMessageId ?? "") !== proof.commitMessageId || nextManifest.mlsEpochHint !== oldManifest.mlsEpochHint + (commitChanged ? 1 : 0)) {
    throw new HttpError(409, "group_transition_invalid", "group transition MLS epoch or commit is not contiguous");
  }
  if (proof.operation !== groupTransitionProofOperation(operation)) {
    throw new HttpError(409, "group_transition_invalid", "group transition operation does not match membership proof");
  }
  let valid = false;
  switch (operation.type) {
    case "create":
      valid = oldManifest.rosterVersion === 0 && oldManifest.mlsEpochHint === 0 && oldManifest.ownerUserId === nextManifest.ownerUserId && genesisTransitionIsWellFormed(oldManifest, nextManifest) && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.members = nextManifest.members;
        expected.memberDevices = nextManifest.memberDevices;
        expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
      });
      break;
    case "invite_members": {
      const oldIds = new Set(oldManifest.members.map((member) => member.userId));
      const addedIds = nextManifest.members.filter((member) => !oldIds.has(member.userId)).map((member) => member.userId).sort();
      valid = membershipAdditionsAreWellFormed(oldManifest, nextManifest) && sameJson([...new Set(operation.userIds)].sort(), addedIds) && membershipDeviceAdditionsAreWellFormed(oldManifest, nextManifest, new Set(addedIds)) && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.members = nextManifest.members;
        expected.memberDevices = nextManifest.memberDevices;
        expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
      });
      break;
    }
    case "approve_join": {
      const oldUser = oldManifest.members.find((member) => member.userId === operation.userId);
      const nextUser = nextManifest.members.find((member) => member.userId === operation.userId);
      const addedUsers = nextManifest.members.filter((member) => !oldManifest.members.some((old) => old.userId === member.userId));
      const nextDevice = (nextManifest.memberDevices ?? []).find((device) => device.userId === operation.userId && device.deviceId === operation.deviceId && device.status === "active");
      valid = !oldUser && addedUsers.length === 1 && addedUsers[0].userId === operation.userId && nextUser?.role === "member" && nextUser.status === "active" && Boolean(nextDevice) && membershipAdditionsAreWellFormed(oldManifest, nextManifest) && membershipDeviceAdditionsAreWellFormed(oldManifest, nextManifest, /* @__PURE__ */ new Set([operation.userId])) && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.members = nextManifest.members;
        expected.memberDevices = nextManifest.memberDevices;
        expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
      });
      break;
    }
    case "approve_leave":
    case "remove_member": {
      const targetUserId = operation.userId;
      const oldTarget = oldManifest.members.find((member) => member.userId === targetUserId);
      const nextTarget = nextManifest.members.find((member) => member.userId === targetUserId);
      const expectedStatus = operation.type === "approve_leave" ? "left" : "removed";
      valid = memberRemovalIsWellFormed(oldManifest, nextManifest, expectedStatus) && Boolean(oldTarget && nextTarget && oldTarget.status === "active" && nextTarget.status === expectedStatus) && memberDevicesForRemovalAreWellFormed(oldManifest, nextManifest, targetUserId) && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.members = nextManifest.members;
        expected.memberDevices = nextManifest.memberDevices;
        expected.admins = nextManifest.admins;
        expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
      });
      break;
    }
    case "add_device":
      valid = deviceAdditionIsWellFormed(oldManifest, nextManifest) && (nextManifest.memberDevices ?? []).some((device) => device.userId === operation.userId && device.deviceId === operation.deviceId && device.status === "active") && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.memberDevices = nextManifest.memberDevices;
        expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
      });
      break;
    case "remove_device":
      valid = deviceRemovalIsWellFormed(oldManifest, nextManifest) && (nextManifest.memberDevices ?? []).some((device) => device.userId === operation.userId && device.deviceId === operation.deviceId && device.status === "removed") && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.memberDevices = nextManifest.memberDevices;
        expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
      });
      break;
    case "update_metadata":
      valid = (oldManifest.title !== nextManifest.title || oldManifest.joinPolicy !== nextManifest.joinPolicy || oldManifest.memberInvitePolicy !== nextManifest.memberInvitePolicy) && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.title = nextManifest.title;
        expected.joinPolicy = nextManifest.joinPolicy;
        expected.memberInvitePolicy = nextManifest.memberInvitePolicy;
      });
      break;
    case "set_admin":
      valid = adminUpdateIsWellFormed(oldManifest, nextManifest) && nextManifest.members.some((member) => member.userId === operation.userId && member.status === "active" && member.role === (operation.isAdmin ? "admin" : "member")) && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.members = nextManifest.members;
        expected.admins = nextManifest.admins;
      });
      break;
    case "transfer_ownership":
      valid = ownershipTransferIsWellFormed(oldManifest, nextManifest) && nextManifest.ownerUserId === operation.userId && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.ownerUserId = nextManifest.ownerUserId;
        expected.members = nextManifest.members;
        expected.admins = nextManifest.admins;
      });
      break;
    case "dissolve":
      valid = dissolveTransitionIsWellFormed(oldManifest, nextManifest) && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.members = nextManifest.members;
        expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
      });
      break;
  }
  if (!valid) {
    throw new HttpError(409, "group_transition_invalid", `manifest changes do not match ${operation.type}`);
  }
}
function groupTransitionProofOperation(operation) {
  switch (operation.type) {
    case "invite_members":
      return "invite";
    case "approve_leave":
      return "leave";
    case "remove_member":
      return "remove";
    default:
      return operation.type;
  }
}
var GroupAuthorizationService = class {
  constructor(groupId, storage) {
    this.groupId = groupId;
    this.storage = storage;
  }
  async getState() {
    return this.storage.get(GROUP_AUTHORIZATION_KEY);
  }
  async getPublicState() {
    const state = await this.getState();
    if (!state) {
      throw new HttpError(428, "group_authorization_uninitialized", "group authorization has not been initialized");
    }
    return {
      manifest: state.manifest,
      manifestHash: await groupManifestSha256(state.manifest),
      lastTransitionId: state.lastTransitionId,
      phase: state.phase ?? (state.manifest.rosterVersion === 0 ? "provisioning" : "active"),
      materialized: (state.phase ?? (state.manifest.rosterVersion === 0 ? "provisioning" : "active")) === "active"
    };
  }
  async initialize(input, runtimeToken, now) {
    if (input.version !== CURRENT_MODEL_VERSION || input.groupId !== this.groupId) {
      throw new HttpError(400, "unsupported_version", "group authorization bootstrap scope is invalid");
    }
    validateManifestShape(input.manifest, this.groupId);
    if (runtimeToken.userId !== input.manifest.ownerUserId) {
      throw new HttpError(403, "invalid_capability", "only the transport owner's active group owner can bootstrap authorization");
    }
    const existing = await this.getState();
    if (existing) {
      if (!sameJson(existing.manifest, input.manifest)) {
        throw new HttpError(409, "group_authorization_conflict", "group authorization is already initialized with a different manifest");
      }
      return {
        initialized: true,
        alreadyInitialized: true,
        rosterVersion: existing.manifest.rosterVersion,
        lastCommitMessageId: existing.manifest.lastCommitMessageId
      };
    }
    const devices = mergeVerifiedDevices({}, input.identityBundles);
    validateManifestDevices(input.manifest, devices);
    verifyManifestSignature(input.manifest, devices);
    const state = {
      version: "2",
      manifest: input.manifest,
      devices,
      initializedAt: now,
      updatedAt: now,
      phase: input.manifest.rosterVersion === 0 ? "provisioning" : "active"
    };
    await this.storage.put(GROUP_AUTHORIZATION_KEY, state);
    return {
      initialized: true,
      alreadyInitialized: false,
      rosterVersion: input.manifest.rosterVersion,
      lastCommitMessageId: input.manifest.lastCommitMessageId
    };
  }
  async authorize(request, capability, operation, allowedRoles, now, allowInactiveMember = false, allowProvisioning = false) {
    const state = await this.getState();
    if (!state) {
      throw new HttpError(428, "group_authorization_uninitialized", "group authorization has not been initialized");
    }
    const phase = state.phase ?? (state.manifest.rosterVersion === 0 ? "provisioning" : "active");
    if (phase === "provisioning" && !allowProvisioning) {
      throw new HttpError(428, "group_membership_uninitialized", "group membership has not completed its genesis transition");
    }
    const authorization = request.headers.get("Authorization")?.trim();
    const bearer = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
    if (capability.version !== CURRENT_MODEL_VERSION || capability.service !== "group_outbox" || capability.groupId !== this.groupId || !bearer || bearer !== capability.signature || !Number.isSafeInteger(capability.expiresAt) || capability.expiresAt <= now || capability.expiresAt - now > MAX_CAPABILITY_TTL_MS || !capability.operations.includes(operation)) {
      throw new HttpError(403, "invalid_capability", "group capability is invalid or expired");
    }
    const device = state.devices[deviceKey2(capability.userId, capability.deviceId)];
    const knownMember = state.manifest.members.find((item) => item.userId === capability.userId);
    const knownManifestDevice = (state.manifest.memberDevices ?? []).find(
      (item) => item.userId === capability.userId && item.deviceId === capability.deviceId
    );
    const hasValidDeviceSignature = Boolean(
      device && device.status === "active" && verifyEd25519(device.publicKey, capability.signature, groupCapabilitySigningPayload(capability))
    );
    if (hasValidDeviceSignature && (knownMember?.status !== "active" || knownManifestDevice?.status !== "active")) {
      throw new HttpError(403, "group_membership_revoked", "group membership has been revoked");
    }
    const member = allowInactiveMember ? knownMember : activeMember(state.manifest, capability.userId);
    const manifestDevice = knownManifestDevice?.status === "active" ? knownManifestDevice : void 0;
    if (!device || device.status !== "active" || !manifestDevice || !member || !hasValidDeviceSignature) {
      throw new HttpError(403, "invalid_capability", "group capability device signature or membership is invalid");
    }
    if (!allowedRoles.includes(member.role) || !ROLE_OPERATIONS[member.role].has(operation)) {
      throw new HttpError(403, "invalid_capability", `current group role cannot use ${operation}`);
    }
    return { state, role: member.role };
  }
  async prepareUpdate(current, update, proof, now, operation) {
    if (!proof && !update) {
      return void 0;
    }
    if (!proof || !update) {
      throw new HttpError(409, "group_transition_invalid", "membership proof and authorizationUpdate must be supplied together");
    }
    validateManifestShape(update.manifest, this.groupId);
    const devices = mergeVerifiedDevices(current.devices, update.identityBundles);
    validateManifestDevices(update.manifest, devices);
    const manifestHash = await groupManifestSha256(update.manifest);
    if (manifestHash !== proof.newManifestSha256) {
      throw new HttpError(409, "group_transition_invalid", "group manifest hash does not match membership proof");
    }
    verifyManifestSignature(update.manifest, devices);
    if (current.manifest.signature === update.manifest.signature) {
      verifyIdempotentMembershipProof(proof, { ...current, devices }, manifestHash);
      return {
        ...current,
        devices,
        lastTransitionProof: proof,
        updatedAt: now
      };
    }
    verifyMembershipProof(proof, current, update.manifest);
    if (!operation) {
      throw new HttpError(409, "group_transition_invalid", "atomic membership transition operation is required");
    }
    validateTransitionShape(current.manifest, update.manifest, proof, operation);
    return {
      ...current,
      manifest: update.manifest,
      devices,
      lastTransitionProof: proof,
      updatedAt: now,
      phase: current.phase === "provisioning" && operation.type === "create" ? "active" : current.phase ?? "active"
    };
  }
  async commitPreparedUpdate(state) {
    if (state) {
      await this.storage.put(GROUP_AUTHORIZATION_KEY, state);
    }
  }
};

// src/group-outbox/service.ts
var META_KEY = "meta";
var IDEMPOTENCY_PREFIX = "idempotency:";
var RECORD_PREFIX = "record:";
var INVITE_PREFIX = "invite:";
var JOIN_REQUEST_PREFIX = "join-request:";
var JOIN_REQUEST_IDEMPOTENCY_PREFIX = "join-request-idempotency:";
var LEAVE_REQUEST_PREFIX = "leave-request:";
var LEAVE_REQUEST_IDEMPOTENCY_PREFIX = "leave-request-idempotency:";
var TRANSITION_PREFIX = "transition:";
var INVITE_REVISION_KEY = "invite-revision";
var JOIN_LEASE_MS = 2 * 60 * 1e3;
function canonicalJson2(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson2).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson2(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
function transitionFingerprint(input) {
  const { capability: _capability, ...stable } = input;
  return canonicalJson2(stable);
}
var GroupOutboxService = class {
  groupId;
  state;
  spillStore;
  defaults;
  sessions;
  constructor(groupId, state, spillStore, defaults, sessions = []) {
    this.groupId = groupId;
    this.state = state;
    this.spillStore = spillStore;
    this.defaults = defaults;
    this.sessions = sessions;
  }
  async appendEnvelope(input, now) {
    await this.rejectIfSealed();
    this.validateAppendRequest(input);
    const existingSeq = await this.state.get(`${IDEMPOTENCY_PREFIX}${input.envelope.messageId}`);
    if (existingSeq !== void 0) {
      return { accepted: true, seq: existingSeq };
    }
    const meta = await this.getMeta();
    const seq = meta.headSeq + 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1e3;
    const record = {
      seq,
      groupId: this.groupId,
      messageId: input.envelope.messageId,
      receivedAt: now,
      expiresAt,
      state: "available",
      envelope: input.envelope
    };
    const serialized = JSON.stringify(record);
    const storageKey = `${RECORD_PREFIX}${seq}`;
    if (new TextEncoder().encode(serialized).byteLength <= meta.maxInlineBytes && input.envelope.inlineCiphertext) {
      await this.state.put(storageKey, {
        seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        inlineRecord: record
      });
    } else {
      const payloadRef = `group-outbox-payload/${this.groupId}/${seq}.json`;
      await this.spillStore.putJson(payloadRef, record);
      await this.state.put(storageKey, {
        seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        payloadRef
      });
    }
    await this.state.put(`${IDEMPOTENCY_PREFIX}${record.messageId}`, seq);
    await this.state.put(META_KEY, { ...meta, headSeq: seq });
    await this.state.setAlarm(expiresAt);
    this.publish({ event: "group_head_updated", groupId: this.groupId, seq });
    this.publish({ event: "group_outbox_record_available", groupId: this.groupId, seq, record });
    return { accepted: true, seq };
  }
  /** Fail closed before parsing or authorizing an append body on a sealed log. */
  async assertWritable() {
    await this.rejectIfSealed();
  }
  async appendTransition(input, preparedAuthorization, now) {
    await this.rejectIfSealed();
    this.validateTransitionRequest(input);
    const transitionKey = `${TRANSITION_PREFIX}${input.transitionId}`;
    const fingerprint = transitionFingerprint(input);
    const existing = await this.state.get(transitionKey);
    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        throw new HttpError(409, "group_transition_conflict", "transition id already exists with different content");
      }
      return existing.result;
    }
    const meta = await this.getMeta();
    const authorization = await this.state.get(GROUP_AUTHORIZATION_KEY);
    if (!authorization) {
      throw new HttpError(428, "group_authorization_uninitialized", "group authorization has not been initialized");
    }
    const storedRosterVersion = authorization.manifest.rosterVersion;
    const storedCommitMessageId = authorization.manifest.lastCommitMessageId ?? "";
    if (meta.currentRosterVersion !== void 0 && meta.currentRosterVersion !== storedRosterVersion || meta.lastCommitMessageId !== void 0 && meta.lastCommitMessageId !== storedCommitMessageId) {
      throw new HttpError(500, "storage_integrity_error", "group outbox meta does not match authorization state");
    }
    const requestBindingEntries = await this.validateAndPrepareRequestBinding(input, now);
    for (const envelope of input.envelopes) {
      const existingSeq = await this.state.get(`${IDEMPOTENCY_PREFIX}${envelope.messageId}`);
      if (existingSeq !== void 0) {
        throw new HttpError(409, "group_transition_conflict", "transition message id already belongs to another record");
      }
    }
    if (input.expectedPreviousRosterVersion !== storedRosterVersion || (input.expectedPreviousCommitMessageId ?? "") !== storedCommitMessageId) {
      throw new HttpError(409, "roster_version_conflict", "group transition base does not match the authoritative roster");
    }
    const firstSeq = meta.headSeq + 1;
    const lastSeq = firstSeq + input.envelopes.length - 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1e3;
    const records = input.envelopes.map((envelope, offset) => ({
      seq: firstSeq + offset,
      groupId: this.groupId,
      messageId: envelope.messageId,
      receivedAt: now,
      expiresAt,
      state: "available",
      envelope
    }));
    const indexes = [];
    for (const record of records) {
      const serialized = JSON.stringify(record);
      const index = {
        seq: record.seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        transitionId: input.transitionId,
        transitionStartSeq: firstSeq,
        transitionEndSeq: lastSeq
      };
      if (new TextEncoder().encode(serialized).byteLength <= meta.maxInlineBytes && record.envelope.inlineCiphertext) {
        index.inlineRecord = record;
      } else {
        const payloadRef = `group-outbox-transition/${this.groupId}/${input.transitionId}/${record.messageId}.json`;
        await this.spillStore.putJson(payloadRef, record);
        index.payloadRef = payloadRef;
      }
      indexes.push([`${RECORD_PREFIX}${record.seq}`, index]);
    }
    const currentMeta = await this.getMeta();
    const currentAuthorization = await this.state.get(GROUP_AUTHORIZATION_KEY);
    if (currentMeta.headSeq !== meta.headSeq || currentMeta.currentRosterVersion !== void 0 && currentMeta.currentRosterVersion !== storedRosterVersion || currentMeta.lastCommitMessageId !== void 0 && currentMeta.lastCommitMessageId !== storedCommitMessageId || !currentAuthorization || currentAuthorization.manifest.signature !== authorization.manifest.signature || currentAuthorization.manifest.rosterVersion !== input.expectedPreviousRosterVersion || (currentAuthorization.manifest.lastCommitMessageId ?? "") !== storedCommitMessageId) {
      throw new HttpError(409, "roster_version_conflict", "group transition base changed while payloads were prepared");
    }
    const result = {
      accepted: true,
      transitionId: input.transitionId,
      firstSeq,
      lastSeq,
      rosterVersion: preparedAuthorization.manifest.rosterVersion,
      lastCommitMessageId: preparedAuthorization.manifest.lastCommitMessageId
    };
    const entries = {
      [META_KEY]: {
        ...meta,
        headSeq: lastSeq,
        currentRosterVersion: preparedAuthorization.manifest.rosterVersion,
        lastCommitMessageId: preparedAuthorization.manifest.lastCommitMessageId
      },
      [GROUP_AUTHORIZATION_KEY]: {
        ...preparedAuthorization,
        lastTransitionId: input.transitionId
      },
      [transitionKey]: { fingerprint, operation: input.operation, requestBinding: input.requestBinding, result },
      ...requestBindingEntries
    };
    for (const [key, index] of indexes) {
      entries[key] = index;
      entries[`${IDEMPOTENCY_PREFIX}${index.messageId}`] = index.seq;
    }
    await this.state.putEntries(entries);
    await this.state.setAlarm(expiresAt);
    for (const record of records) {
      this.publish({ event: "group_head_updated", groupId: this.groupId, seq: record.seq });
      this.publish({ event: "group_outbox_record_available", groupId: this.groupId, seq: record.seq, record });
    }
    return result;
  }
  validateTransitionRequest(input) {
    if (input.groupId !== this.groupId || !input.transitionId || input.envelopes.length < 2 || input.envelopes.length > 3 || !input.operation || typeof input.operation !== "object") {
      throw new HttpError(400, "invalid_input", "group transition must contain one to three envelopes for this group");
    }
    const messageIds = /* @__PURE__ */ new Set();
    let proofJson;
    for (const envelope of input.envelopes) {
      if (envelope.groupId !== this.groupId || envelope.transitionId !== input.transitionId || envelope.senderUserId !== input.capability.userId || envelope.senderDeviceId !== input.capability.deviceId || messageIds.has(envelope.messageId)) {
        throw new HttpError(409, "group_transition_invalid", "group transition envelope binding is invalid");
      }
      messageIds.add(envelope.messageId);
      if (envelope.membershipProof) {
        const nextProofJson = JSON.stringify(envelope.membershipProof);
        if (proofJson && proofJson !== nextProofJson) {
          throw new HttpError(409, "group_transition_invalid", "group transition envelopes carry different membership proofs");
        }
        proofJson = nextProofJson;
      }
    }
    const proof = input.envelopes.find((envelope) => envelope.membershipProof)?.membershipProof;
    if (!proof || proof.operation !== groupTransitionProofOperation(input.operation) || proof.previousRosterVersion !== input.expectedPreviousRosterVersion) {
      throw new HttpError(409, "group_transition_invalid", "group transition proof does not match the request base");
    }
    const commitIsCurrent = proof.commitMessageId === (input.expectedPreviousCommitMessageId ?? "");
    if (!messageIds.has(proof.controlMessageId) || !messageIds.has(proof.commitMessageId) && !commitIsCurrent) {
      throw new HttpError(409, "group_transition_invalid", "group transition proof references records outside the bundle");
    }
    if (proof.stateEventMessageId && !messageIds.has(proof.stateEventMessageId)) {
      throw new HttpError(409, "group_transition_invalid", "group state event is not part of the transition bundle");
    }
    if (!proof.stateEventMessageId) {
      throw new HttpError(409, "group_transition_invalid", "group transition must contain a bound state event");
    }
    const controls = input.envelopes.filter(
      (envelope) => envelope.messageId === proof.controlMessageId && envelope.messageType.startsWith("control_group_")
    );
    const stateEvents = input.envelopes.filter(
      (envelope) => envelope.messageId === proof.stateEventMessageId && envelope.messageType === "control_group_state_event"
    );
    if (controls.length !== 1 || stateEvents.length !== 1) {
      throw new HttpError(409, "group_transition_invalid", "group transition control and state event records are invalid");
    }
  }
  async validateAndPrepareRequestBinding(input, now) {
    const binding = input.requestBinding;
    if (input.operation.type === "approve_join") {
      if (!binding || binding.type !== "join" || binding.requestId !== input.operation.requestId) {
        throw new HttpError(409, "group_join_lease_invalid", "join transition must bind its claimed join request");
      }
      const key = `${JOIN_REQUEST_PREFIX}${binding.requestId}`;
      const stored = await this.state.get(key);
      const lease = stored?.lease;
      if (!stored || stored.request.status !== "transition_in_progress" || stored.request.joinerUserId !== input.operation.userId || stored.request.joinerDeviceId !== input.operation.deviceId || !lease || lease.expiresAt <= now || lease.token !== binding.leaseToken || lease.userId !== input.capability.userId || lease.deviceId !== input.capability.deviceId) {
        throw new HttpError(409, "group_join_lease_invalid", "join transition lease is missing, expired, or does not match the joiner");
      }
      return {
        [key]: {
          ...stored,
          transitionId: input.transitionId,
          committedBinding: { transitionId: input.transitionId, leaseToken: binding.leaseToken, committedAt: now }
        }
      };
    }
    if (input.operation.type === "approve_leave") {
      if (!binding || binding.type !== "leave" || binding.requestId !== input.operation.requestId) {
        throw new HttpError(409, "group_leave_lease_invalid", "leave transition must bind its claimed leave request");
      }
      const key = `${LEAVE_REQUEST_PREFIX}${binding.requestId}`;
      const stored = await this.state.get(key);
      const lease = stored?.lease;
      if (!stored || stored.request.status !== "transition_in_progress" || stored.request.leaverUserId !== input.operation.userId || stored.request.leaverDeviceId !== input.operation.deviceId || !lease || lease.expiresAt <= now || lease.token !== binding.leaseToken || lease.userId !== input.capability.userId || lease.deviceId !== input.capability.deviceId) {
        throw new HttpError(409, "group_leave_lease_invalid", "leave transition lease is missing, expired, or does not match the leaver");
      }
      return {
        [key]: {
          ...stored,
          request: { ...stored.request, status: "completed" },
          transitionId: input.transitionId,
          lease: void 0
        }
      };
    }
    if (binding) {
      throw new HttpError(409, "group_transition_invalid", "request binding is only valid for join or leave transitions");
    }
    return {};
  }
  async fetchOutbox(input) {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group outbox route");
    }
    if (input.limit <= 0) {
      throw new HttpError(400, "invalid_input", "limit must be greater than zero");
    }
    const meta = await this.getMeta();
    const records = [];
    const firstIndex = await this.state.get(`${RECORD_PREFIX}${input.fromSeq}`);
    if (firstIndex?.transitionStartSeq !== void 0 && firstIndex.transitionStartSeq !== input.fromSeq) {
      throw new HttpError(
        409,
        "group_cursor_invalid",
        "requested cursor falls inside a transition bundle",
        { bundleStartSeq: firstIndex.transitionStartSeq }
      );
    }
    let upper = Math.min(meta.headSeq, input.fromSeq + input.limit - 1);
    const boundaryIndex = await this.state.get(`${RECORD_PREFIX}${upper}`);
    if (boundaryIndex?.transitionEndSeq !== void 0) {
      upper = Math.min(meta.headSeq, Math.max(upper, boundaryIndex.transitionEndSeq));
    }
    for (let seq = input.fromSeq; seq <= upper; seq += 1) {
      const index = await this.state.get(`${RECORD_PREFIX}${seq}`);
      if (!index) {
        throw new HttpError(500, "storage_integrity_error", `group record index is missing at seq ${seq}`);
      }
      this.validateStoredRecordIndex(index, seq);
      if (index.inlineRecord) {
        this.validateMaterializedRecord(index.inlineRecord, index, seq);
        records.push(index.inlineRecord);
        continue;
      }
      if (!index.payloadRef) {
        throw new HttpError(500, "storage_integrity_error", `group record payload reference is missing at seq ${seq}`);
      }
      let record;
      try {
        record = await this.spillStore.getJson(index.payloadRef);
      } catch {
        throw new HttpError(500, "storage_integrity_error", `group spill payload is invalid at seq ${seq}`);
      }
      if (!record) {
        throw new HttpError(500, "storage_integrity_error", `group spill payload is missing at seq ${seq}`);
      }
      this.validateMaterializedRecord(record, index, seq);
      records.push(record);
    }
    return {
      toSeq: records.length > 0 ? records[records.length - 1].seq : meta.headSeq,
      records
    };
  }
  async getHead() {
    const meta = await this.getMeta();
    return {
      headSeq: meta.headSeq,
      currentRosterVersion: meta.currentRosterVersion,
      lastCommitMessageId: meta.lastCommitMessageId
    };
  }
  validateStoredRecordIndex(index, seq) {
    if (index.seq !== seq || index.groupId !== this.groupId || !index.messageId) {
      throw new HttpError(500, "storage_integrity_error", `group record index does not match seq ${seq}`);
    }
  }
  validateMaterializedRecord(record, index, seq) {
    if (record.seq !== seq || record.seq !== index.seq || record.messageId !== index.messageId || record.groupId !== this.groupId || record.groupId !== index.groupId) {
      throw new HttpError(500, "storage_integrity_error", `group record payload does not match index at seq ${seq}`);
    }
  }
  async createInvite(input, inviteUrl, token, now) {
    if (input.groupId !== this.groupId || input.document.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group invite route");
    }
    await this.rejectIfSealed();
    this.validateInviteDocument(input.document, now);
    const key = `${INVITE_PREFIX}${input.document.inviteId}`;
    const existing = await this.state.get(key);
    if (existing) {
      const { signature: _storedToken, ...storedDocument } = existing.document;
      const { signature: _requestedSignature, ...requestedDocument } = input.document;
      if (canonicalJson2(storedDocument) !== canonicalJson2(requestedDocument) || existing.maxUses !== (input.maxUses ?? input.document.maxUses)) {
        throw new HttpError(409, "conflict", "invite id already exists with a different document");
      }
      return { inviteUrl: existing.inviteUrl, invite: existing.document };
    }
    const stored = {
      inviteUrl,
      token,
      document: { ...input.document, signature: token },
      uses: 0,
      maxUses: input.maxUses ?? input.document.maxUses
    };
    const revision = await this.state.get(INVITE_REVISION_KEY) ?? 0;
    await this.state.putEntries({ [key]: stored, [INVITE_REVISION_KEY]: revision + 1 });
    await this.scheduleNextAlarm(now);
    this.publish({ event: "group_invites_changed", groupId: this.groupId, revision: revision + 1 });
    return { inviteUrl, invite: stored.document };
  }
  async listInvites(now) {
    await this.processAlarm(now);
    const rows = await this.state.list({ prefix: INVITE_PREFIX });
    const invites = Array.from(rows.values()).filter((stored) => stored.document.groupId === this.groupId).map((stored) => ({
      inviteUrl: stored.inviteUrl,
      invite: stored.document,
      status: stored.revokedAt !== void 0 ? "revoked" : stored.document.expiresAt <= now ? "expired" : stored.maxUses !== void 0 && stored.uses >= stored.maxUses ? "exhausted" : "active",
      uses: stored.uses,
      maxUses: stored.maxUses,
      revokedAt: stored.revokedAt,
      expiredAt: stored.expiredAt,
      exhaustedAt: stored.exhaustedAt
    })).sort((left, right) => right.invite.createdAt - left.invite.createdAt);
    return { revision: await this.state.get(INVITE_REVISION_KEY) ?? 0, invites };
  }
  async fetchInvite(payload, now) {
    if (payload.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "invite token group does not match route");
    }
    const stored = await this.loadUsableInvite(payload.inviteId, now);
    if (stored.token !== stored.document.signature) {
      throw new HttpError(403, "invalid_capability", "invite signature is invalid");
    }
    return { invite: stored.document };
  }
  async fetchInviteById(inviteId, now) {
    const stored = await this.loadUsableInvite(inviteId, now);
    if (stored.token !== stored.document.signature) {
      throw new HttpError(403, "invalid_capability", "invite signature is invalid");
    }
    return { invite: stored.document };
  }
  async revokeInvite(input, now) {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group invite route");
    }
    await this.rejectIfSealed();
    const key = `${INVITE_PREFIX}${input.inviteId}`;
    const stored = await this.state.get(key);
    if (!stored) {
      throw new HttpError(404, "not_found", "invite not found");
    }
    if (stored.revokedAt !== void 0) {
      return { accepted: true, inviteId: input.inviteId };
    }
    const revision = await this.state.get(INVITE_REVISION_KEY) ?? 0;
    await this.state.putEntries({
      [key]: { ...stored, revokedAt: now },
      [INVITE_REVISION_KEY]: revision + 1
    });
    this.publish({ event: "group_invites_changed", groupId: this.groupId, revision: revision + 1 });
    await this.scheduleNextAlarm(now);
    return { accepted: true, inviteId: input.inviteId };
  }
  async submitJoinRequest(input, payload, now) {
    if (payload.groupId !== this.groupId || input.request.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "join request group does not match route");
    }
    await this.rejectIfSealed();
    if (payload.inviteId !== input.request.inviteId) {
      throw new HttpError(403, "invalid_capability", "join request invite does not match bearer token");
    }
    const invite = await this.loadUsableInvite(payload.inviteId, now);
    if (invite.document.joinPolicy === "closed") {
      throw new HttpError(403, "invalid_invite", "invite does not allow link join requests");
    }
    this.validateJoinRequest(input.request, now);
    const idempotencyKey = `${JOIN_REQUEST_IDEMPOTENCY_PREFIX}${encodeURIComponent(payload.inviteId)}:${encodeURIComponent(input.request.joinerUserId)}:${encodeURIComponent(input.request.joinerDeviceId)}`;
    const existingRequestId = await this.state.get(idempotencyKey);
    if (existingRequestId) {
      const existingByIdentity = await this.state.get(`${JOIN_REQUEST_PREFIX}${existingRequestId}`);
      if (existingByIdentity) {
        return {
          accepted: true,
          request: existingByIdentity.request,
          autoApprove: existingByIdentity.request.autoApprove
        };
      }
    }
    const key = `${JOIN_REQUEST_PREFIX}${input.request.requestId}`;
    const existing = await this.state.get(key);
    if (existing) {
      if (JSON.stringify(existing.request) !== JSON.stringify(input.request)) {
        throw new HttpError(409, "conflict", "join request id already exists with different content");
      }
      return {
        accepted: true,
        request: existing.request,
        autoApprove: existing.request.autoApprove
      };
    }
    const request = {
      ...input.request,
      status: invite.document.joinPolicy === "open_by_invite" ? "waiting_for_group_commit" : "pending_approval",
      autoApprove: invite.document.joinPolicy === "open_by_invite"
    };
    const inviteRevision = await this.state.get(INVITE_REVISION_KEY) ?? 0;
    const nextUses = invite.uses + 1;
    const exhaustedAt = invite.maxUses !== void 0 && nextUses >= invite.maxUses ? now : invite.exhaustedAt;
    await this.state.putEntries({
      [key]: { request },
      [idempotencyKey]: request.requestId,
      [`${INVITE_PREFIX}${payload.inviteId}`]: {
        ...invite,
        uses: nextUses,
        exhaustedAt
      },
      [INVITE_REVISION_KEY]: inviteRevision + 1
    });
    this.publish({ event: "group_invites_changed", groupId: this.groupId, revision: inviteRevision + 1 });
    this.publish(
      request.status === "pending_approval" ? { event: "group_join_request_available", groupId: this.groupId, requestId: request.requestId } : { event: "group_auto_join_available", groupId: this.groupId, requestId: request.requestId }
    );
    await this.scheduleNextAlarm(now);
    return { accepted: true, request, autoApprove: request.autoApprove };
  }
  async listJoinRequests() {
    const result = await this.state.list({ prefix: JOIN_REQUEST_PREFIX });
    const requests = Array.from(result.values()).map((stored) => stored.request).filter(
      (request) => request.groupId === this.groupId && ["pending", "pending_approval", "waiting_for_group_commit", "transition_in_progress"].includes(request.status)
    ).sort((a, b) => a.requestedAt - b.requestedAt || a.requestId.localeCompare(b.requestId));
    return { requests };
  }
  async getJoinRequestStatus(requestId, requestCapability) {
    const stored = await this.state.get(`${JOIN_REQUEST_PREFIX}${requestId}`);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    if (stored.request.requestCapability !== requestCapability) {
      throw new HttpError(403, "invalid_capability", "join request capability does not match bearer token");
    }
    if (!["approved", "welcome_available", "joined"].includes(stored.request.status)) {
      return { request: stored.request };
    }
    return {
      request: stored.request,
      welcomePickup: stored.welcomePickup,
      manifest: stored.manifest,
      startCursor: stored.startCursor
    };
  }
  async claimJoinRequest(input, now) {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group join route");
    }
    await this.rejectIfSealed();
    const key = `${JOIN_REQUEST_PREFIX}${input.requestId}`;
    const stored = await this.state.get(key);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    if (!["waiting_for_group_commit", "transition_in_progress"].includes(stored.request.status)) {
      throw new HttpError(409, "group_join_terminal", "join request is already terminal");
    }
    if (stored.lease && stored.lease.expiresAt > now) {
      if (stored.lease.userId === input.capability.userId && stored.lease.deviceId === input.capability.deviceId) {
        return {
          accepted: true,
          request: stored.request,
          leaseToken: stored.lease.token,
          leaseExpiresAt: stored.lease.expiresAt
        };
      }
      throw new HttpError(409, "group_join_claimed", "join request is claimed by another administrator device");
    }
    const lease = {
      token: crypto.randomUUID(),
      userId: input.capability.userId,
      deviceId: input.capability.deviceId,
      expiresAt: now + JOIN_LEASE_MS
    };
    const request = { ...stored.request, status: "transition_in_progress" };
    await this.state.put(key, { ...stored, request, lease });
    await this.state.setAlarm(lease.expiresAt);
    return {
      accepted: true,
      request,
      leaseToken: lease.token,
      leaseExpiresAt: lease.expiresAt
    };
  }
  async completeJoinRequest(input, now) {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group join route");
    }
    await this.rejectIfSealed();
    const key = `${JOIN_REQUEST_PREFIX}${input.requestId}`;
    const stored = await this.state.get(key);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    const completionFingerprint = canonicalJson2({
      transitionId: input.transitionId,
      leaseToken: input.leaseToken,
      welcomePickup: input.welcomePickup,
      manifest: input.manifest,
      startCursor: input.startCursor
    });
    if (["welcome_available", "joined"].includes(stored.request.status)) {
      if (stored.transitionId === input.transitionId && stored.completionFingerprint === completionFingerprint) {
        return { accepted: true, request: stored.request };
      }
      throw new HttpError(409, "group_transition_conflict", "join completion differs from the stored completion");
    }
    const lease = stored.lease;
    const committed = stored.committedBinding;
    if (stored.request.status !== "transition_in_progress" || !lease || !committed || committed.transitionId !== input.transitionId || committed.leaseToken !== input.leaseToken || lease.token !== input.leaseToken || lease.userId !== input.capability.userId || lease.deviceId !== input.capability.deviceId) {
      throw new HttpError(409, "group_join_lease_invalid", "join request lease is missing, expired, or owned by another device");
    }
    const authorization = await this.state.get(GROUP_AUTHORIZATION_KEY);
    const transition = await this.state.get(`${TRANSITION_PREFIX}${input.transitionId}`);
    const manifestHash = await groupManifestSha256(input.manifest);
    const authorizationHash = authorization ? await groupManifestSha256(authorization.manifest) : "";
    const member = input.manifest.members.find((item) => item.userId === stored.request.joinerUserId && item.status === "active");
    const device = (input.manifest.memberDevices ?? []).find(
      (item) => item.userId === stored.request.joinerUserId && item.deviceId === stored.request.joinerDeviceId && item.status === "active"
    );
    if (!authorization || !transition || transition.requestBinding?.type !== "join" || transition.requestBinding.requestId !== input.requestId || transition.requestBinding.leaseToken !== input.leaseToken || transition.operation.type !== "approve_join" || authorization.lastTransitionId !== input.transitionId || authorizationHash !== manifestHash || !member || !device || input.welcomePickup.groupId !== this.groupId || input.welcomePickup.deviceId !== stored.request.joinerDeviceId || input.welcomePickup.requestId !== input.requestId || input.startCursor.groupId !== this.groupId || input.startCursor.lastFetchedSeq !== transition.result.lastSeq || input.startCursor.lastFetchedSeq !== input.welcomePickup.startSeq || input.welcomePickup.rosterVersion !== transition.result.rosterVersion || (input.welcomePickup.lastCommitMessageId ?? "") !== (transition.result.lastCommitMessageId ?? "")) {
      throw new HttpError(409, "group_transition_invalid", "join completion does not match the committed group transition");
    }
    const request = { ...stored.request, status: "welcome_available" };
    await this.state.put(key, {
      ...stored,
      request,
      welcomePickup: input.welcomePickup,
      manifest: input.manifest,
      startCursor: input.startCursor,
      transitionId: input.transitionId,
      lease: void 0,
      completionFingerprint
    });
    return { accepted: true, request };
  }
  async markWelcomeClaimed(requestId, deviceId, capability) {
    const key = `${JOIN_REQUEST_PREFIX}${requestId}`;
    const stored = await this.state.get(key);
    if (!stored || stored.request.status !== "welcome_available" || stored.request.joinerDeviceId !== deviceId || stored.welcomePickup?.requestId !== requestId || stored.welcomePickup.capability !== capability) {
      throw new HttpError(409, "group_transition_invalid", "welcome claim does not match the completed join request");
    }
    await this.state.put(key, { ...stored, request: { ...stored.request, status: "joined" } });
  }
  async authorizeWelcomeUpload(requestId, deviceId, capability) {
    const stored = await this.state.get(`${JOIN_REQUEST_PREFIX}${requestId}`);
    if (!stored || stored.request.status !== "transition_in_progress" || !stored.committedBinding || stored.request.joinerDeviceId !== deviceId || !capability) {
      throw new HttpError(409, "group_transition_invalid", "welcome upload is not bound to a committed join transition");
    }
  }
  async submitLeaveRequest(input, now) {
    if (input.groupId !== this.groupId || input.request.groupId !== this.groupId || input.request.leaverUserId !== input.capability.userId || input.request.leaverDeviceId !== input.capability.deviceId) {
      throw new HttpError(400, "invalid_input", "leave request does not match its route or capability");
    }
    await this.rejectIfSealed();
    if (!input.request.requestId || !input.request.requestCapability || !input.request.signature || input.request.requestedAt > now + 5 * 60 * 1e3) {
      throw new HttpError(400, "invalid_input", "leave request is malformed");
    }
    const authorization = await this.state.get(GROUP_AUTHORIZATION_KEY);
    if (authorization?.manifest.ownerUserId === input.request.leaverUserId) {
      throw new HttpError(409, "group_transition_invalid", "group owner must transfer ownership before leaving");
    }
    const idempotencyKey = `${LEAVE_REQUEST_IDEMPOTENCY_PREFIX}${encodeURIComponent(input.request.leaverUserId)}:${encodeURIComponent(input.request.leaverDeviceId)}`;
    const existingId = await this.state.get(idempotencyKey);
    if (existingId) {
      const existing2 = await this.state.get(`${LEAVE_REQUEST_PREFIX}${existingId}`);
      if (existing2) return { accepted: true, request: existing2.request };
    }
    const key = `${LEAVE_REQUEST_PREFIX}${input.request.requestId}`;
    const existing = await this.state.get(key);
    if (existing) {
      if (canonicalJson2(existing.request) !== canonicalJson2({ ...input.request, status: existing.request.status })) {
        throw new HttpError(409, "group_transition_conflict", "leave request id already exists with different content");
      }
      return { accepted: true, request: existing.request };
    }
    const request = { ...input.request, status: "waiting_for_group_commit" };
    await this.state.putEntries({ [key]: { request }, [idempotencyKey]: request.requestId });
    this.publish({ event: "group_leave_request_available", groupId: this.groupId, requestId: request.requestId });
    return { accepted: true, request };
  }
  async listLeaveRequests() {
    const rows = await this.state.list({ prefix: LEAVE_REQUEST_PREFIX });
    return {
      requests: Array.from(rows.values()).map((stored) => stored.request).filter((request) => request.groupId === this.groupId && ["waiting_for_group_commit", "transition_in_progress"].includes(request.status)).sort((a, b) => a.requestedAt - b.requestedAt || a.requestId.localeCompare(b.requestId))
    };
  }
  async claimLeaveRequest(input, now) {
    if (input.groupId !== this.groupId) throw new HttpError(400, "invalid_input", "leave request group does not match route");
    await this.rejectIfSealed();
    const key = `${LEAVE_REQUEST_PREFIX}${input.requestId}`;
    const stored = await this.state.get(key);
    if (!stored) throw new HttpError(404, "not_found", "leave request not found");
    if (!["waiting_for_group_commit", "transition_in_progress"].includes(stored.request.status)) {
      throw new HttpError(409, "group_leave_terminal", "leave request is already terminal");
    }
    if (stored.lease && stored.lease.expiresAt > now) {
      if (stored.lease.userId === input.capability.userId && stored.lease.deviceId === input.capability.deviceId) {
        return { accepted: true, request: stored.request, leaseToken: stored.lease.token, leaseExpiresAt: stored.lease.expiresAt };
      }
      throw new HttpError(409, "group_leave_claimed", "leave request is claimed by another administrator device");
    }
    const lease = { token: crypto.randomUUID(), userId: input.capability.userId, deviceId: input.capability.deviceId, expiresAt: now + JOIN_LEASE_MS };
    const request = { ...stored.request, status: "transition_in_progress" };
    await this.state.put(key, { ...stored, request, lease });
    await this.scheduleNextAlarm(now);
    return { accepted: true, request, leaseToken: lease.token, leaseExpiresAt: lease.expiresAt };
  }
  async decideJoinRequest(input) {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group join route");
    }
    await this.rejectIfSealed();
    const key = `${JOIN_REQUEST_PREFIX}${input.requestId}`;
    const stored = await this.state.get(key);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    if (!["pending", "pending_approval"].includes(stored.request.status)) {
      throw new HttpError(409, "conflict", "join request is already terminal");
    }
    if (input.decision === "approve") {
      const request2 = { ...stored.request, status: "waiting_for_group_commit" };
      await this.state.put(key, { ...stored, request: request2 });
      this.publish({ event: "group_auto_join_available", groupId: this.groupId, requestId: request2.requestId });
      return { accepted: true, request: request2 };
    }
    if (input.decision === "reject" && (input.welcomePickup || input.manifest || input.startCursor)) {
      throw new HttpError(400, "invalid_input", "rejected join request must not include welcome pickup, manifest, or start cursor");
    }
    const request = {
      ...stored.request,
      status: "rejected"
    };
    const updated = {
      request,
      welcomePickup: void 0,
      manifest: void 0,
      startCursor: void 0,
      reason: input.decision === "reject" ? input.reason : void 0
    };
    await this.state.put(key, updated);
    return { accepted: true, request };
  }
  async processAlarm(now) {
    const entries = {};
    let inviteChanged = false;
    const invites = await this.state.list({ prefix: INVITE_PREFIX });
    for (const [key, stored] of invites) {
      if (stored.revokedAt === void 0 && stored.expiredAt === void 0 && stored.document.expiresAt <= now) {
        entries[key] = { ...stored, expiredAt: now };
        inviteChanged = true;
      } else if (stored.revokedAt === void 0 && stored.exhaustedAt === void 0 && stored.maxUses !== void 0 && stored.uses >= stored.maxUses) {
        entries[key] = { ...stored, exhaustedAt: now };
        inviteChanged = true;
      }
    }
    const joins = await this.state.list({ prefix: JOIN_REQUEST_PREFIX });
    for (const [key, stored] of joins) {
      if (stored.request.status === "transition_in_progress" && stored.lease && stored.lease.expiresAt <= now && !stored.committedBinding) {
        entries[key] = { ...stored, request: { ...stored.request, status: "waiting_for_group_commit" }, lease: void 0 };
        this.publish({ event: "group_auto_join_available", groupId: this.groupId, requestId: stored.request.requestId });
      }
    }
    const leaves = await this.state.list({ prefix: LEAVE_REQUEST_PREFIX });
    for (const [key, stored] of leaves) {
      if (stored.request.status === "transition_in_progress" && stored.lease && stored.lease.expiresAt <= now) {
        entries[key] = { ...stored, request: { ...stored.request, status: "waiting_for_group_commit" }, lease: void 0 };
        this.publish({ event: "group_leave_request_available", groupId: this.groupId, requestId: stored.request.requestId });
      }
    }
    if (inviteChanged) {
      const revision = await this.state.get(INVITE_REVISION_KEY) ?? 0;
      entries[INVITE_REVISION_KEY] = revision + 1;
      this.publish({ event: "group_invites_changed", groupId: this.groupId, revision: revision + 1 });
    }
    if (Object.keys(entries).length > 0) await this.state.putEntries(entries);
    await this.scheduleNextAlarm(now);
  }
  async scheduleNextAlarm(now) {
    const deadlines = [];
    const invites = await this.state.list({ prefix: INVITE_PREFIX });
    for (const stored of invites.values()) {
      if (stored.revokedAt === void 0 && stored.expiredAt === void 0 && stored.document.expiresAt > now) deadlines.push(stored.document.expiresAt);
    }
    const joins = await this.state.list({ prefix: JOIN_REQUEST_PREFIX });
    for (const stored of joins.values()) if (stored.lease && !stored.committedBinding && stored.lease.expiresAt > now) deadlines.push(stored.lease.expiresAt);
    const leaves = await this.state.list({ prefix: LEAVE_REQUEST_PREFIX });
    for (const stored of leaves.values()) if (stored.lease && stored.lease.expiresAt > now) deadlines.push(stored.lease.expiresAt);
    if (deadlines.length > 0) await this.state.setAlarm(Math.min(...deadlines));
  }
  async getMeta() {
    return await this.state.get(META_KEY) ?? this.defaults;
  }
  /**
   * Idempotent seal of the group outbox. The very first caller flips
   * `sealed = true` and records `sealedAt = now`; subsequent callers are
   * rejected with HTTP 409 `already_sealed` regardless of their
   * capability (PROTOCOL_GROUP_CN.md §10.4 — seals are irreversible).
   *
   * Callers must already have authenticated owner-signed
   * `seal_group` capability at the transport layer; this method only
   * enforces the storage-side invariant.
   */
  async sealOutbox(now) {
    const meta = await this.getMeta();
    if (meta.sealed === true) {
      throw new HttpError(409, "already_sealed", "group outbox is already sealed");
    }
    const nextMeta = { ...meta, sealed: true, sealedAt: now };
    await this.state.put(META_KEY, nextMeta);
    return { sealed: true, sealedAt: now, wasAlreadySealed: false };
  }
  async getSealStatus() {
    const meta = await this.getMeta();
    return { sealed: meta.sealed === true, sealedAt: meta.sealedAt ?? 0 };
  }
  /**
   * Reject any append-type flow on a sealed outbox with the canonical
   * `403 group_sealed` response. Reads (fetch / head / subscribe-replay)
   * are explicitly allowed to continue, so only write paths call this.
   */
  async rejectIfSealed() {
    const meta = await this.getMeta();
    if (meta.sealed === true) {
      throw new HttpError(403, "group_sealed", "group outbox is sealed and cannot accept new writes");
    }
  }
  validateAppendRequest(input) {
    if (input.groupId !== this.groupId || input.envelope.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group outbox route");
    }
    this.validateEnvelope(input.envelope);
  }
  async loadUsableInvite(inviteId, now) {
    await this.processAlarm(now);
    const stored = await this.state.get(`${INVITE_PREFIX}${inviteId}`);
    if (!stored || stored.document.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "invite not found");
    }
    if (stored.revokedAt !== void 0) {
      throw new HttpError(403, "invalid_invite", "invite is revoked");
    }
    if (stored.expiredAt !== void 0 || stored.document.expiresAt <= now) {
      throw new HttpError(403, "capability_expired", "invite is expired");
    }
    if (stored.exhaustedAt !== void 0 || stored.maxUses !== void 0 && stored.uses >= stored.maxUses) {
      throw new HttpError(403, "invalid_invite", "invite max uses exceeded");
    }
    return stored;
  }
  validateInviteDocument(document, now) {
    if (!document.groupId || !document.inviteId || !document.title || !document.inviterUserId || !document.inviterDeviceId || !document.ownerUserId || !document.joinRequestEndpoint || !document.signature) {
      throw new HttpError(400, "invalid_input", "invite document is missing required fields");
    }
    if (document.expiresAt <= now) {
      throw new HttpError(400, "invalid_input", "invite must not already be expired");
    }
  }
  validateJoinRequest(request, now) {
    if (!request.requestId || !request.groupId || !request.inviteId || !request.joinerUserId || !request.joinerDeviceId || !request.joinerContactShareUrl || !request.requestCapability || !request.signature) {
      throw new HttpError(400, "invalid_input", "join request is missing required fields");
    }
    if (request.requestedAt > now + 5 * 60 * 1e3) {
      throw new HttpError(400, "invalid_input", "join request timestamp is too far in the future");
    }
  }
  validateEnvelope(envelope) {
    if (!envelope.messageId || !envelope.groupId || !envelope.conversationId || !envelope.senderUserId || !envelope.senderDeviceId) {
      throw new HttpError(400, "invalid_input", "group envelope is missing required fields");
    }
    if (!envelope.senderProof?.type || !envelope.senderProof.value) {
      throw new HttpError(400, "invalid_input", "group envelope sender proof is required");
    }
    const hasInline = Boolean(envelope.inlineCiphertext);
    const hasStorageRefs = (envelope.storageRefs?.length ?? 0) > 0;
    if (!hasInline && !hasStorageRefs) {
      throw new HttpError(400, "invalid_input", "group envelope must include inline_ciphertext or storage_refs");
    }
  }
  publish(event) {
    const payload = JSON.stringify(event);
    for (const session of this.sessions) {
      session.send(payload);
    }
  }
};

// src/group-outbox/durable.ts
var DurableObjectStorageAdapter = class {
  storage;
  constructor(storage) {
    this.storage = storage;
  }
  async get(key) {
    return await this.storage.get(key) ?? void 0;
  }
  async put(key, value) {
    await this.storage.put(key, value);
  }
  async putEntries(entries) {
    await this.storage.put(entries);
  }
  async mutateEntries(entries, deleteKeys) {
    await this.storage.transaction(async (transaction) => {
      if (Object.keys(entries).length > 0) {
        await transaction.put(entries);
      }
      if (deleteKeys.length > 0) {
        await transaction.delete(deleteKeys);
      }
    });
  }
  async delete(key) {
    await this.storage.delete(key);
  }
  async list(options) {
    return this.storage.list(options);
  }
  async setAlarm(epochMillis) {
    await this.storage.setAlarm(epochMillis);
  }
};
var R2JsonBlobStore = class {
  bucket;
  constructor(bucket) {
    this.bucket = bucket;
  }
  async putJson(key, value) {
    await this.bucket.put(key, JSON.stringify(value));
  }
  async getJson(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return await object.json();
  }
  async putBytes(key, value) {
    await this.bucket.put(key, value);
  }
  async getBytes(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return object.arrayBuffer();
  }
  async delete(key) {
    await this.bucket.delete(key);
  }
};
function versionedBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return body;
  }
  const record = body;
  if (record.version !== void 0) {
    return body;
  }
  return {
    version: "0.1",
    ...record
  };
}
function jsonResponse2(body, status = 200) {
  return new Response(JSON.stringify(versionedBody(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}
var DurableObjectBase2 = globalThis.DurableObject ?? class {
  constructor(_state, _env) {
  }
};
async function handleGroupOutboxDurableRequest(request, deps) {
  const now = deps.now ?? Date.now();
  const url = new URL(request.url);
  const service = new GroupOutboxService(deps.groupId, deps.state, deps.spillStore, {
    headSeq: 0,
    retentionDays: deps.retentionDays,
    maxInlineBytes: deps.maxInlineBytes
  }, deps.sessions);
  const authorization = new GroupAuthorizationService(deps.groupId, deps.state);
  try {
    if (url.pathname.endsWith("/authorization/bootstrap") && request.method === "POST") {
      const runtimeToken = await validateAnyDeviceRuntimeAuthorization(
        request,
        deps.deviceRuntimeSecrets,
        "group_authorization_bootstrap",
        now
      );
      if (deps.assertRuntimeToken) await deps.assertRuntimeToken(runtimeToken);
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      return jsonResponse2(await authorization.initialize(body, runtimeToken, now));
    }
    if (url.pathname.endsWith("/subscribe") && deps.onUpgrade) {
      await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "subscribe",
        ["owner", "admin", "member"],
        now
      );
      return deps.onUpgrade();
    }
    if (url.pathname.endsWith("/outbox/transitions") && request.method === "POST") {
      const body = await readJsonLimited(request, DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES);
      if (!body.capability || body.groupId !== deps.groupId) {
        throw new HttpError(403, "invalid_capability", "missing or mismatched group transition capability");
      }
      let authState;
      const isCreate = body.operation?.type === "create";
      for (const envelope of body.envelopes ?? []) {
        if (envelope.senderUserId !== body.capability.userId || envelope.senderDeviceId !== body.capability.deviceId) {
          throw new HttpError(403, "invalid_capability", "group capability does not match transition sender");
        }
        for (const operation of requiredGroupAppendOperations(envelope.messageType)) {
          authState = await authorization.authorize(
            request,
            body.capability,
            operation,
            allowedGroupAppendRoles(envelope.messageType),
            now,
            false,
            isCreate
          );
        }
      }
      if (!authState) {
        throw new HttpError(400, "invalid_input", "group transition contains no envelopes");
      }
      if (isCreate && authState.role !== "owner") {
        throw new HttpError(403, "invalid_capability", "only the current owner may commit group genesis");
      }
      const authoritativeManifest = authState.state.manifest;
      if (body.expectedPreviousRosterVersion !== authoritativeManifest.rosterVersion || (body.expectedPreviousCommitMessageId ?? "") !== (authoritativeManifest.lastCommitMessageId ?? "")) {
        throw new HttpError(409, "roster_version_conflict", "group transition base does not match the authoritative roster");
      }
      const proof = body.envelopes.find((envelope) => envelope.membershipProof)?.membershipProof;
      const preparedUpdate = await authorization.prepareUpdate(
        authState.state,
        body.authorizationUpdate,
        proof,
        now,
        body.operation
      );
      if (!preparedUpdate) {
        throw new HttpError(409, "group_transition_invalid", "group transition did not produce an authorization update");
      }
      return jsonResponse2(await service.appendTransition(body, preparedUpdate, now));
    }
    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = await readJsonLimited(request, DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES);
      await service.assertWritable();
      if (!body?.envelope) {
        throw new HttpError(400, "invalid_input", "group append envelope is required");
      }
      if (body.envelope.membershipProof) {
        throw new HttpError(409, "group_transition_required", "membership operations must use the atomic transition endpoint");
      }
      if (!body.capability) {
        throw new HttpError(403, "invalid_capability", "missing group capability");
      }
      if (body.envelope.senderUserId !== body.capability.userId || body.envelope.senderDeviceId !== body.capability.deviceId) {
        throw new HttpError(403, "invalid_capability", "group capability does not match envelope sender");
      }
      const requiredOperations = requiredGroupAppendOperations(body.envelope.messageType);
      let authState;
      for (const operation of requiredOperations) {
        authState = await authorization.authorize(
          request,
          body.capability,
          operation,
          allowedGroupAppendRoles(body.envelope.messageType),
          now
        );
      }
      const preparedUpdate = await authorization.prepareUpdate(
        authState.state,
        body.authorizationUpdate,
        body.envelope.membershipProof,
        now
      );
      const result = await service.appendEnvelope(body, now);
      await authorization.commitPreparedUpdate(preparedUpdate);
      return jsonResponse2(result);
    }
    if (url.pathname.endsWith("/messages") && request.method === "GET") {
      const fromSeq = Number(url.searchParams.get("fromSeq") ?? "1");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const capability = JSON.parse(request.headers.get("X-Tapchat-Group-Capability") ?? "{}");
      const sealed = (await service.getSealStatus()).sealed;
      await authorization.authorize(
        request,
        capability,
        "read",
        ["owner", "admin", "member"],
        now,
        sealed
      );
      return jsonResponse2(await service.fetchOutbox({
        groupId: deps.groupId,
        fromSeq,
        limit,
        capability
      }));
    }
    if (url.pathname.endsWith("/head") && request.method === "GET") {
      const sealed = (await service.getSealStatus()).sealed;
      const auth = await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "read",
        ["owner", "admin", "member"],
        now,
        sealed
      );
      const head = await service.getHead();
      return jsonResponse2({
        ...head,
        currentRosterVersion: auth.state.manifest.rosterVersion,
        lastCommitMessageId: auth.state.manifest.lastCommitMessageId
      });
    }
    if (url.pathname.endsWith("/authorization/state") && request.method === "GET") {
      await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "read",
        ["owner", "admin", "member"],
        now,
        false,
        true
      );
      return jsonResponse2(await authorization.getPublicState());
    }
    if (url.pathname.endsWith("/outbox/seal") && request.method === "POST") {
      const capability = readGroupCapabilityHeader(request);
      await authorization.authorize(request, capability, "seal_group", ["owner"], now);
      return jsonResponse2(await service.sealOutbox(now));
    }
    if (url.pathname.match(/\/v1\/groups\/[^/]+\/invites$/) && request.method === "POST") {
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "manage_invites", ["owner", "admin"], now);
      const token = await signSharingPayload(deps.sharingSecret, {
        version: body.document.version,
        service: "group_invite",
        groupId: deps.groupId,
        inviteId: body.document.inviteId,
        inviterUserId: body.document.inviterUserId,
        inviterDeviceId: body.document.inviterDeviceId,
        joinPolicy: body.document.joinPolicy,
        expiresAt: body.document.expiresAt,
        maxUses: body.maxUses ?? body.document.maxUses
      });
      return jsonResponse2(
        await service.createInvite(
          body,
          `${url.origin}/v1/group-invite/${encodeURIComponent(deps.groupId)}/${encodeURIComponent(body.document.inviteId)}`,
          token,
          now
        )
      );
    }
    if (url.pathname.match(/\/v1\/groups\/[^/]+\/invites$/) && request.method === "GET") {
      await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "manage_invites",
        ["owner", "admin"],
        now
      );
      return jsonResponse2(await service.listInvites(now));
    }
    const shortInviteFetchMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)\/([^/]+)$/);
    if (shortInviteFetchMatch && request.method === "GET") {
      const routeGroupId = decodeURIComponent(shortInviteFetchMatch[1]);
      if (routeGroupId !== deps.groupId) {
        throw new HttpError(400, "invalid_input", "group invite route does not match durable object");
      }
      return jsonResponse2(await service.fetchInviteById(decodeURIComponent(shortInviteFetchMatch[2]), now));
    }
    const inviteFetchMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)$/);
    if (inviteFetchMatch && request.method === "GET") {
      const payload = await verifyInviteToken(deps.sharingSecret, decodeURIComponent(inviteFetchMatch[1]), now);
      return jsonResponse2(await service.fetchInvite(payload, now));
    }
    const revokeMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/invites\/([^/]+)\/revoke$/);
    if (revokeMatch && request.method === "POST") {
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "manage_invites", ["owner", "admin"], now);
      return jsonResponse2(
        await service.revokeInvite(
          {
            version: body.version,
            groupId: deps.groupId,
            inviteId: decodeURIComponent(revokeMatch[1]),
            capability: body.capability
          },
          now
        )
      );
    }
    const joinCollectionMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests$/);
    if (joinCollectionMatch && request.method === "POST") {
      const token = getBearerToken(request);
      const payload = await verifyInviteToken(deps.sharingSecret, token, now);
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      return jsonResponse2(await service.submitJoinRequest({ ...body, inviteToken: token }, payload, now));
    }
    if (joinCollectionMatch && request.method === "GET") {
      await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "approve_join",
        ["owner", "admin"],
        now
      );
      return jsonResponse2(await service.listJoinRequests());
    }
    const joinStatusMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)$/);
    if (joinStatusMatch && request.method === "GET") {
      return jsonResponse2(await service.getJoinRequestStatus(decodeURIComponent(joinStatusMatch[1]), getBearerToken(request)));
    }
    const leaveCollectionMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/leave-requests$/);
    if (leaveCollectionMatch && request.method === "POST") {
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "append_control", ["admin", "member"], now);
      return jsonResponse2(await service.submitLeaveRequest(body, now));
    }
    if (leaveCollectionMatch && request.method === "GET") {
      await authorization.authorize(request, readGroupCapabilityHeader(request), "approve_join", ["owner", "admin"], now);
      return jsonResponse2(await service.listLeaveRequests());
    }
    const leaveClaimMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/leave-requests\/([^/]+)\/claim$/);
    if (leaveClaimMatch && request.method === "POST") {
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "approve_join", ["owner", "admin"], now);
      return jsonResponse2(await service.claimLeaveRequest({ ...body, groupId: deps.groupId, requestId: decodeURIComponent(leaveClaimMatch[1]) }, now));
    }
    const claimMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)\/claim$/);
    if (claimMatch && request.method === "POST") {
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "approve_join", ["owner", "admin"], now);
      return jsonResponse2(
        await service.claimJoinRequest(
          { ...body, groupId: deps.groupId, requestId: decodeURIComponent(claimMatch[1]) },
          now
        )
      );
    }
    const completeMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)\/complete$/);
    if (completeMatch && request.method === "POST") {
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "approve_join", ["owner", "admin"], now);
      return jsonResponse2(
        await service.completeJoinRequest(
          { ...body, groupId: deps.groupId, requestId: decodeURIComponent(completeMatch[1]) },
          now
        )
      );
    }
    if (url.pathname.endsWith("/internal/welcome-claimed") && request.method === "POST") {
      if (request.headers.get("X-Tapchat-Internal-Secret") !== deps.sharingSecret) {
        throw new HttpError(403, "invalid_capability", "internal welcome claim authorization failed");
      }
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      if (!body.deviceId || !body.requestId || !body.capability) {
        throw new HttpError(400, "invalid_input", "welcome claim request, device and capability are required");
      }
      await service.markWelcomeClaimed(body.requestId, body.deviceId, body.capability);
      return jsonResponse2({ accepted: true });
    }
    if (url.pathname.endsWith("/internal/welcome-authorize") && request.method === "POST") {
      if (request.headers.get("X-Tapchat-Internal-Secret") !== deps.sharingSecret) {
        throw new HttpError(403, "invalid_capability", "internal welcome authorization failed");
      }
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      if (!body.deviceId || !body.requestId || !body.capability) throw new HttpError(400, "invalid_input", "welcome authorization binding is required");
      await service.authorizeWelcomeUpload(body.requestId, body.deviceId, body.capability);
      return jsonResponse2({ accepted: true });
    }
    const decisionMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)\/decision$/);
    if (decisionMatch && request.method === "POST") {
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "approve_join", ["owner", "admin"], now);
      return jsonResponse2(
        await service.decideJoinRequest({
          ...body,
          groupId: deps.groupId,
          requestId: decodeURIComponent(decisionMatch[1])
        })
      );
    }
    return jsonResponse2({ error: "not_found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      return jsonResponse2({ error: error.code, message: error.message, ...error.details ? { details: error.details } : {} }, error.status);
    }
    const runtimeError = error;
    const message = runtimeError.message ?? "internal error";
    return jsonResponse2({ error: "temporary_unavailable", message }, 500);
  }
}
async function verifyInviteToken(secret, token, now) {
  try {
    const payload = await verifySharingPayload(secret, token, now);
    if (payload.version !== "0.1" || payload.service !== "group_invite" || !payload.groupId || !payload.inviteId) {
      throw new Error("malformed group invite token");
    }
    return payload;
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid group invite token";
    if (message.includes("expired")) {
      throw new HttpError(403, "capability_expired", message);
    }
    throw new HttpError(403, "invalid_capability", message);
  }
}
async function groupIdFromGroupOutboxRequestUrl(url, sharingSecret, now) {
  const groupMatch = url.pathname.match(/\/v1\/groups\/([^/]+)\//);
  let groupId = decodeURIComponent(groupMatch?.[1] ?? "");
  if (!groupId) {
    const shortInviteMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)\/([^/]+)$/);
    if (shortInviteMatch) {
      groupId = decodeURIComponent(shortInviteMatch[1]);
    }
  }
  if (!groupId) {
    const inviteMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)$/);
    if (inviteMatch) {
      const payload = await verifyInviteToken(
        sharingSecret,
        decodeURIComponent(inviteMatch[1]),
        now
      );
      groupId = payload.groupId;
    }
  }
  return groupId;
}
var GroupOutboxDurableObject = class extends DurableObjectBase2 {
  sessions = /* @__PURE__ */ new Map();
  stateRef;
  envRef;
  groupIdRef;
  constructor(state, env) {
    super(state, env);
    this.stateRef = state;
    this.envRef = env;
  }
  async fetch(request) {
    const url = new URL(request.url);
    let sharingSecret;
    let deviceRuntimeSecrets2;
    try {
      sharingSecret = requireSharingSecret(this.envRef);
      deviceRuntimeSecrets2 = requireDeviceRuntimeSecrets(this.envRef);
    } catch (error) {
      if (error instanceof HttpError) {
        return jsonResponse2({ error: error.code, message: error.message }, error.status);
      }
      return jsonResponse2({ error: "runtime_misconfigured", message: "sharing secret is invalid" }, 503);
    }
    const groupId = await groupIdFromGroupOutboxRequestUrl(url, sharingSecret, Date.now());
    this.groupIdRef = groupId;
    await this.stateRef.storage.put("durable-group-id", groupId);
    return handleGroupOutboxDurableRequest(request, {
      groupId,
      state: new DurableObjectStorageAdapter(this.stateRef.storage),
      spillStore: new R2JsonBlobStore(this.envRef.TAPCHAT_STORAGE),
      sessions: Array.from(this.sessions.values()).map(
        (session) => ({
          send(payload) {
            return session.send(payload);
          }
        })
      ),
      maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096"),
      retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"),
      sharingSecret,
      deviceRuntimeSecrets: deviceRuntimeSecrets2,
      assertRuntimeToken: (token) => assertRegisteredRuntimeToken(this.envRef, token),
      onUpgrade: () => {
        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        server.accept();
        const sessionId = crypto.randomUUID();
        const removeSession = () => {
          this.sessions.delete(sessionId);
        };
        const session = new ManagedSession(server, removeSession);
        this.sessions.set(sessionId, session);
        server.addEventListener("close", () => {
          session.terminate();
        });
        server.addEventListener("error", (event) => {
          event.preventDefault();
          session.terminate();
        });
        return new Response(null, {
          status: 101,
          webSocket: client
        });
      }
    });
  }
  async alarm() {
    const groupId = this.groupIdRef ?? await this.stateRef.storage.get("durable-group-id");
    if (!groupId) return;
    const service = new GroupOutboxService(
      groupId,
      new DurableObjectStorageAdapter(this.stateRef.storage),
      new R2JsonBlobStore(this.envRef.TAPCHAT_STORAGE),
      { headSeq: 0, retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"), maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096") },
      Array.from(this.sessions.values()).map((session) => ({ send: (payload) => session.send(payload) }))
    );
    await service.processAlarm(Date.now());
  }
};
var ManagedSession = class {
  socket;
  onClosed;
  closed = false;
  constructor(socket, onClosed) {
    this.socket = socket;
    this.onClosed = onClosed;
  }
  send(payload) {
    if (this.closed) {
      return false;
    }
    if (this.socket.readyState !== 1) {
      this.finish(false);
      return false;
    }
    try {
      this.socket.send(payload);
      return true;
    } catch {
      this.close();
      return false;
    }
  }
  close() {
    this.finish(true);
  }
  terminate() {
    this.finish(false);
  }
  finish(closeSocket) {
    if (this.closed) {
      return;
    }
    this.closed = true;
    if (closeSocket) {
      try {
        this.socket.close(1011, "session closed");
      } catch {
      }
    }
    this.onClosed();
  }
};

// src/inbox/service.ts
var META_KEY2 = "meta";
var IDEMPOTENCY_PREFIX2 = "idempotency:";
var APPEND_RESULT_PREFIX = "append-result:";
var RECORD_PREFIX2 = "record:";
var ALLOWLIST_KEY = "allowlist";
var MESSAGE_REQUEST_PREFIX = "message-request:";
var RATE_LIMIT_PREFIX = "rate-limit:";
var MESSAGE_REQUEST_META_KEY = `${MESSAGE_REQUEST_PREFIX}meta`;
var MESSAGE_REQUEST_RATE_LIMIT_KEY = `${MESSAGE_REQUEST_PREFIX}rate-limit`;
var CLEANUP_BATCH_SIZE = 128;
var InboxService = class {
  deviceId;
  state;
  spillStore;
  sessions;
  defaults;
  constructor(deviceId, state, spillStore, sessions, defaults) {
    this.deviceId = deviceId;
    this.state = state;
    this.spillStore = spillStore;
    this.sessions = sessions;
    this.defaults = defaults;
  }
  async appendEnvelope(input, now, authContext = { mode: "verified" }) {
    this.validateAppendRequest(input);
    const existingResult = await this.state.get(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`);
    if (existingResult) {
      return existingResult;
    }
    await this.enforceRateLimit(input.envelope.senderUserId, now);
    const allowlist = await this.getAllowlist(now);
    if (allowlist.rejectedSenderUserIds.includes(input.envelope.senderUserId)) {
      const rejected = {
        accepted: true,
        seq: 0,
        deliveredTo: "rejected",
        queuedAsRequest: false
      };
      await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, rejected);
      return rejected;
    }
    if (authContext.mode !== "verified") {
      const request2 = await this.queueMessageRequestWithLimit(input, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, request2);
      return request2;
    }
    if (allowlist.allowedSenderUserIds.includes(input.envelope.senderUserId)) {
      const delivered = await this.deliverEnvelope(input, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, delivered);
      return delivered;
    }
    const request = await this.queueMessageRequestWithLimit(input, now);
    await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, request);
    return request;
  }
  async fetchMessages(input) {
    if (input.deviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "device_id does not match inbox route");
    }
    if (input.limit <= 0) {
      throw new HttpError(400, "invalid_input", "limit must be greater than zero");
    }
    const meta = await this.getMeta();
    const records = [];
    const upper = Math.min(meta.headSeq, input.fromSeq + input.limit - 1);
    for (let seq = input.fromSeq; seq <= upper; seq += 1) {
      const index = await this.state.get(`${RECORD_PREFIX2}${seq}`);
      if (!index) {
        if (seq <= meta.ackedSeq) {
          continue;
        }
        throw new HttpError(500, "storage_integrity_error", `inbox record index is missing at seq ${seq}`);
      }
      this.validateStoredRecordIndex(index, seq);
      if (index.inlineRecord) {
        this.validateMaterializedRecord(index.inlineRecord, index, seq);
        records.push(index.inlineRecord);
        continue;
      }
      if (!index.payloadRef) {
        throw new HttpError(500, "storage_integrity_error", `inbox record payload reference is missing at seq ${seq}`);
      }
      let record;
      try {
        record = await this.spillStore.getJson(index.payloadRef);
      } catch {
        throw new HttpError(500, "storage_integrity_error", `inbox spill payload is invalid at seq ${seq}`);
      }
      if (!record) {
        throw new HttpError(500, "storage_integrity_error", `inbox spill payload is missing at seq ${seq}`);
      }
      this.validateMaterializedRecord(record, index, seq);
      records.push(record);
    }
    return {
      toSeq: records.length > 0 ? records[records.length - 1].seq : meta.headSeq,
      records
    };
  }
  async ack(input) {
    if (input.ack.deviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "ack device_id does not match inbox route");
    }
    const meta = await this.getMeta();
    if (!Number.isSafeInteger(input.ack.ackSeq) || input.ack.ackSeq < 0) {
      throw new HttpError(400, "invalid_ack", "ack_seq must be a non-negative safe integer");
    }
    if (input.ack.ackSeq < meta.ackedSeq) {
      throw new HttpError(409, "invalid_ack", "ack_seq must not move backwards");
    }
    if (input.ack.ackSeq > meta.headSeq) {
      throw new HttpError(409, "invalid_ack", "ack_seq must not move beyond inbox head_seq");
    }
    const ackSeq = input.ack.ackSeq;
    if (ackSeq > meta.ackedSeq) {
      await this.state.put(META_KEY2, { ...meta, ackedSeq: ackSeq });
      await this.state.setAlarm(Date.now());
    }
    return { accepted: true, ackSeq };
  }
  async getHead() {
    const meta = await this.getMeta();
    return { headSeq: meta.headSeq };
  }
  async getAllowlist(now = Date.now()) {
    return await this.state.get(ALLOWLIST_KEY) ?? {
      version: "0.1",
      deviceId: this.deviceId,
      updatedAt: now,
      allowedSenderUserIds: [],
      rejectedSenderUserIds: []
    };
  }
  async replaceAllowlist(allowedSenderUserIds, rejectedSenderUserIds, now) {
    const document = {
      version: "0.1",
      deviceId: this.deviceId,
      updatedAt: now,
      allowedSenderUserIds: Array.from(new Set(allowedSenderUserIds)).sort(),
      rejectedSenderUserIds: Array.from(new Set(rejectedSenderUserIds.filter((userId) => !allowedSenderUserIds.includes(userId)))).sort()
    };
    await this.state.put(ALLOWLIST_KEY, document);
    return document;
  }
  async listMessageRequests(now = Date.now()) {
    await this.pruneExpiredMessageRequests(now);
    await this.scheduleNextAlarm(now);
    const requests = await this.state.get(this.messageRequestIndexKey());
    if (!requests?.length) {
      return [];
    }
    const items = [];
    for (const senderUserId of requests) {
      const entry = await this.state.get(this.messageRequestKey(senderUserId));
      if (!entry) {
        continue;
      }
      items.push(this.toMessageRequestItem(entry));
    }
    items.sort((left, right) => left.firstSeenAt - right.firstSeenAt || left.senderUserId.localeCompare(right.senderUserId));
    return items;
  }
  async acceptMessageRequest(requestId, now) {
    const entry = await this.findMessageRequest(requestId, now);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    const allowlist = await this.getAllowlist(now);
    await this.replaceAllowlist(
      [...allowlist.allowedSenderUserIds, entry.senderUserId],
      allowlist.rejectedSenderUserIds.filter((userId) => userId !== entry.senderUserId),
      now
    );
    const requestsToPromote = this.messageRequestsToPromote(entry);
    const promotedMessageIds = new Set(
      requestsToPromote.map((request) => request.envelope.messageId)
    );
    for (const request of entry.pendingRequests) {
      if (promotedMessageIds.has(request.envelope.messageId)) {
        continue;
      }
      await this.state.put(
        `${APPEND_RESULT_PREFIX}${request.envelope.messageId}`,
        this.supersededMessageRequestResult()
      );
    }
    let promotedCount = 0;
    const promotedConversationIds = /* @__PURE__ */ new Set();
    for (const request of requestsToPromote) {
      const delivered = await this.deliverEnvelope(request, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${request.envelope.messageId}`, delivered);
      if (delivered.deliveredTo === "inbox") {
        promotedCount += 1;
        promotedConversationIds.add(request.envelope.conversationId);
      }
    }
    await this.deleteMessageRequest(entry.senderUserId, "accepted");
    await this.scheduleNextAlarm(now);
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      promotedCount,
      promotedConversationIds: [...promotedConversationIds].sort()
    };
  }
  async rejectMessageRequest(requestId, now) {
    const entry = await this.findMessageRequest(requestId, now);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    const allowlist = await this.getAllowlist(now);
    await this.replaceAllowlist(
      allowlist.allowedSenderUserIds.filter((userId) => userId !== entry.senderUserId),
      [...allowlist.rejectedSenderUserIds, entry.senderUserId],
      now
    );
    await this.deleteMessageRequest(entry.senderUserId, "rejected");
    await this.scheduleNextAlarm(now);
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      promotedCount: 0,
      promotedConversationIds: []
    };
  }
  async cleanExpiredRecords(now) {
    await this.pruneExpiredMessageRequests(now);
    const meta = await this.getMeta();
    const stored = await this.state.list({ prefix: RECORD_PREFIX2 });
    const eligible = Array.from(stored.entries()).filter(([, index]) => index.seq <= meta.ackedSeq && index.expiresAt !== void 0 && index.expiresAt <= now).sort((left, right) => left[1].seq - right[1].seq);
    for (const [key, index] of eligible.slice(0, CLEANUP_BATCH_SIZE)) {
      if (index.payloadRef) {
        await this.spillStore.delete(index.payloadRef);
      }
      await this.state.delete(key);
      await this.state.delete(`${IDEMPOTENCY_PREFIX2}${index.messageId}`);
    }
    if (eligible.length > CLEANUP_BATCH_SIZE) {
      await this.state.setAlarm(now + 1);
      return;
    }
    await this.scheduleNextAlarm(now);
  }
  validateStoredRecordIndex(index, seq) {
    if (index.seq !== seq || index.recipientDeviceId !== this.deviceId || !index.messageId) {
      throw new HttpError(500, "storage_integrity_error", `inbox record index does not match seq ${seq}`);
    }
  }
  validateMaterializedRecord(record, index, seq) {
    if (record.seq !== seq || record.seq !== index.seq || record.messageId !== index.messageId || record.recipientDeviceId !== this.deviceId || record.recipientDeviceId !== index.recipientDeviceId) {
      throw new HttpError(500, "storage_integrity_error", `inbox record payload does not match index at seq ${seq}`);
    }
  }
  async getMeta() {
    return await this.state.get(META_KEY2) ?? this.defaults;
  }
  async deliverEnvelope(input, now) {
    const meta = await this.getMeta();
    const existingSeq = await this.state.get(`${IDEMPOTENCY_PREFIX2}${input.envelope.messageId}`);
    if (existingSeq !== void 0) {
      return { accepted: true, seq: existingSeq, deliveredTo: "inbox" };
    }
    const seq = meta.headSeq + 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1e3;
    const record = {
      seq,
      recipientDeviceId: this.deviceId,
      messageId: input.envelope.messageId,
      receivedAt: now,
      expiresAt,
      state: "available",
      envelope: input.envelope
    };
    const serialized = JSON.stringify(record);
    const storageKey = `${RECORD_PREFIX2}${seq}`;
    if (new TextEncoder().encode(serialized).byteLength <= meta.maxInlineBytes && input.envelope.inlineCiphertext) {
      const inlineIndex = {
        seq,
        messageId: record.messageId,
        recipientDeviceId: record.recipientDeviceId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        inlineRecord: record
      };
      await this.state.put(storageKey, inlineIndex);
    } else {
      const payloadRef = `inbox-payload/${this.deviceId}/${seq}.json`;
      await this.spillStore.putJson(payloadRef, record);
      const indexed = {
        seq,
        messageId: record.messageId,
        recipientDeviceId: record.recipientDeviceId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        payloadRef
      };
      await this.state.put(storageKey, indexed);
    }
    await this.state.put(`${IDEMPOTENCY_PREFIX2}${record.messageId}`, seq);
    await this.state.put(META_KEY2, { ...meta, headSeq: seq });
    this.publish({
      event: "head_updated",
      deviceId: this.deviceId,
      seq
    });
    this.publish({
      event: "inbox_record_available",
      deviceId: this.deviceId,
      seq,
      record
    });
    return { accepted: true, seq, deliveredTo: "inbox" };
  }
  async queueMessageRequestWithLimit(input, now) {
    await this.enforceMessageRequestRateLimit(now);
    await this.pruneExpiredMessageRequests(now);
    const limits = await this.getMeta();
    const senderUserId = input.envelope.senderUserId;
    const key = this.messageRequestKey(senderUserId);
    const requestId = this.requestIdForSender(senderUserId);
    const existing = await this.state.get(key);
    const index = await this.state.get(this.messageRequestIndexKey()) ?? [];
    const queueMeta = await this.state.get(MESSAGE_REQUEST_META_KEY) ?? {
      version: 1,
      totalBytes: 0,
      senderCount: index.length
    };
    const requestBytes = new TextEncoder().encode(JSON.stringify(input)).byteLength;
    if (existing && existing.pendingRequests.length >= (limits.messageRequestMaxPerSender ?? 16)) {
      this.messageRequestCapacityExceeded("message request sender quota exceeded");
    }
    if (!existing && index.length >= (limits.messageRequestMaxSenders ?? 64)) {
      this.messageRequestCapacityExceeded("message request sender capacity exceeded");
    }
    if (queueMeta.totalBytes + requestBytes > (limits.messageRequestMaxTotalBytes ?? 4 * 1024 * 1024)) {
      this.messageRequestCapacityExceeded("message request byte capacity exceeded");
    }
    const entry = existing ?? {
      requestId,
      recipientDeviceId: this.deviceId,
      senderUserId,
      senderBundleShareUrl: input.senderBundleShareUrl,
      senderBundleHash: input.senderBundleHash,
      senderDisplayName: input.senderDisplayName,
      firstSeenAt: now,
      lastSeenAt: now,
      messageCount: 0,
      lastMessageId: input.envelope.messageId,
      lastConversationId: input.envelope.conversationId,
      pendingRequests: [],
      byteSize: 0,
      expiresAt: now + (limits.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60) * 1e3
    };
    entry.senderBundleShareUrl ??= input.senderBundleShareUrl;
    entry.senderBundleHash ??= input.senderBundleHash;
    entry.senderDisplayName ??= input.senderDisplayName;
    entry.lastSeenAt = now;
    entry.messageCount += 1;
    entry.lastMessageId = input.envelope.messageId;
    entry.lastConversationId = input.envelope.conversationId;
    entry.pendingRequests.push(input);
    entry.byteSize = (entry.byteSize ?? this.messageRequestEntryBytes(entry) - requestBytes) + requestBytes;
    entry.expiresAt ??= entry.firstSeenAt + (limits.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60) * 1e3;
    const nextIndex = index.includes(senderUserId) ? index : [...index, senderUserId].sort();
    const nextQueueMeta = {
      version: 1,
      totalBytes: queueMeta.totalBytes + requestBytes,
      senderCount: nextIndex.length
    };
    await this.state.putEntries({
      [key]: entry,
      [this.messageRequestIndexKey()]: nextIndex,
      [MESSAGE_REQUEST_META_KEY]: nextQueueMeta
    });
    await this.scheduleNextAlarm(now);
    this.publish({
      event: "message_request_changed",
      deviceId: this.deviceId,
      senderUserId,
      requestId,
      change: "queued"
    });
    return {
      accepted: true,
      seq: 0,
      deliveredTo: "message_request",
      queuedAsRequest: true,
      requestId
    };
  }
  messageRequestCapacityExceeded(message) {
    throw new HttpError(429, "message_request_capacity_exceeded", message);
  }
  messageRequestsToPromote(entry) {
    if (this.groupInviteMetadata(entry)) {
      return entry.pendingRequests;
    }
    const latestConversationId = entry.lastConversationId || entry.pendingRequests[entry.pendingRequests.length - 1]?.envelope.conversationId;
    if (!latestConversationId) {
      return [];
    }
    return entry.pendingRequests.filter(
      (request) => request.envelope.conversationId === latestConversationId
    );
  }
  supersededMessageRequestResult() {
    return {
      accepted: true,
      seq: 0,
      deliveredTo: "rejected",
      queuedAsRequest: false
    };
  }
  async enforceRateLimit(senderUserId, now) {
    const meta = await this.getMeta();
    const minuteLimit = meta.rateLimitPerMinute;
    const hourLimit = meta.rateLimitPerHour;
    if (minuteLimit <= 0 && hourLimit <= 0) {
      return;
    }
    const key = `${RATE_LIMIT_PREFIX}${senderUserId}`;
    const minuteWindowStart = Math.floor(now / 6e4) * 6e4;
    const hourWindowStart = Math.floor(now / 36e5) * 36e5;
    const state = await this.state.get(key) ?? {
      minuteWindowStart,
      minuteCount: 0,
      hourWindowStart,
      hourCount: 0
    };
    if (state.minuteWindowStart !== minuteWindowStart) {
      state.minuteWindowStart = minuteWindowStart;
      state.minuteCount = 0;
    }
    if (state.hourWindowStart !== hourWindowStart) {
      state.hourWindowStart = hourWindowStart;
      state.hourCount = 0;
    }
    if (minuteLimit > 0 && state.minuteCount >= minuteLimit) {
      throw new HttpError(429, "rate_limited", "append rate limit exceeded for minute window");
    }
    if (hourLimit > 0 && state.hourCount >= hourLimit) {
      throw new HttpError(429, "rate_limited", "append rate limit exceeded for hour window");
    }
    state.minuteCount += 1;
    state.hourCount += 1;
    await this.state.put(key, state);
  }
  async enforceMessageRequestRateLimit(now) {
    const meta = await this.getMeta();
    const minuteLimit = meta.messageRequestRateLimitMinute ?? 30;
    const hourLimit = meta.messageRequestRateLimitHour ?? 300;
    const minuteWindowStart = Math.floor(now / 6e4) * 6e4;
    const hourWindowStart = Math.floor(now / 36e5) * 36e5;
    const state = await this.state.get(MESSAGE_REQUEST_RATE_LIMIT_KEY) ?? {
      minuteWindowStart,
      minuteCount: 0,
      hourWindowStart,
      hourCount: 0
    };
    if (state.minuteWindowStart !== minuteWindowStart) {
      state.minuteWindowStart = minuteWindowStart;
      state.minuteCount = 0;
    }
    if (state.hourWindowStart !== hourWindowStart) {
      state.hourWindowStart = hourWindowStart;
      state.hourCount = 0;
    }
    if (minuteLimit > 0 && state.minuteCount >= minuteLimit) {
      throw new HttpError(
        429,
        "message_request_rate_limited",
        "message request rate limit exceeded for minute window",
        { retryAfterSeconds: Math.max(1, Math.ceil((minuteWindowStart + 6e4 - now) / 1e3)) }
      );
    }
    if (hourLimit > 0 && state.hourCount >= hourLimit) {
      throw new HttpError(
        429,
        "message_request_rate_limited",
        "message request rate limit exceeded for hour window",
        { retryAfterSeconds: Math.max(1, Math.ceil((hourWindowStart + 36e5 - now) / 1e3)) }
      );
    }
    state.minuteCount += 1;
    state.hourCount += 1;
    await this.state.put(MESSAGE_REQUEST_RATE_LIMIT_KEY, state);
  }
  publish(event) {
    const payload = JSON.stringify(event);
    for (const session of this.sessions) {
      session.send(payload);
    }
  }
  validateAppendRequest(input) {
    if (input.recipientDeviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "recipient_device_id does not match inbox route");
    }
    if (input.envelope.recipientDeviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "envelope recipient_device_id does not match inbox route");
    }
    if (!input.envelope.messageId || !input.envelope.conversationId || !input.envelope.senderUserId) {
      throw new HttpError(400, "invalid_input", "append request is missing required envelope fields");
    }
    const hasInline = Boolean(input.envelope.inlineCiphertext);
    const hasStorageRefs = (input.envelope.storageRefs?.length ?? 0) > 0;
    if (!hasInline && !hasStorageRefs) {
      throw new HttpError(400, "invalid_input", "envelope must include inline_ciphertext or storage_refs");
    }
  }
  requestIdForSender(senderUserId) {
    return `request:${senderUserId}`;
  }
  messageRequestKey(senderUserId) {
    return `${MESSAGE_REQUEST_PREFIX}${senderUserId}`;
  }
  messageRequestIndexKey() {
    return `${MESSAGE_REQUEST_PREFIX}index`;
  }
  async deleteMessageRequest(senderUserId, change) {
    const existing = await this.state.get(this.messageRequestKey(senderUserId));
    const index = await this.state.get(this.messageRequestIndexKey()) ?? [];
    const nextIndex = index.filter((entry) => entry !== senderUserId);
    const queueMeta = await this.state.get(MESSAGE_REQUEST_META_KEY) ?? {
      version: 1,
      totalBytes: 0,
      senderCount: index.length
    };
    await this.state.mutateEntries({
      [this.messageRequestIndexKey()]: nextIndex,
      [MESSAGE_REQUEST_META_KEY]: {
        version: 1,
        totalBytes: Math.max(0, queueMeta.totalBytes - (existing ? this.messageRequestEntryBytes(existing) : 0)),
        senderCount: nextIndex.length
      }
    }, [this.messageRequestKey(senderUserId)]);
    if (existing) {
      this.publish({
        event: "message_request_changed",
        deviceId: this.deviceId,
        senderUserId,
        requestId: existing.requestId,
        change
      });
    }
  }
  async findMessageRequest(requestId, now) {
    const requests = await this.listMessageRequests(now);
    const match = requests.find((request) => request.requestId === requestId);
    if (!match) {
      return null;
    }
    return await this.state.get(this.messageRequestKey(match.senderUserId)) ?? null;
  }
  messageRequestEntryBytes(entry) {
    if (entry.byteSize !== void 0 && Number.isSafeInteger(entry.byteSize) && entry.byteSize >= 0) {
      return entry.byteSize;
    }
    return entry.pendingRequests.reduce(
      (total, request) => total + new TextEncoder().encode(JSON.stringify(request)).byteLength,
      0
    );
  }
  async pruneExpiredMessageRequests(now) {
    const limits = await this.getMeta();
    const index = await this.state.get(this.messageRequestIndexKey()) ?? [];
    const retained = [];
    const updates = {};
    const deleteKeys = [];
    let totalBytes = 0;
    for (const senderUserId of index) {
      const key = this.messageRequestKey(senderUserId);
      const entry = await this.state.get(key);
      if (!entry) {
        continue;
      }
      const byteSize = this.messageRequestEntryBytes(entry);
      const expiresAt = entry.expiresAt ?? entry.firstSeenAt + (limits.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60) * 1e3;
      if (expiresAt <= now) {
        deleteKeys.push(key);
        for (const pending of entry.pendingRequests) {
          deleteKeys.push(`${APPEND_RESULT_PREFIX}${pending.envelope.messageId}`);
        }
        continue;
      }
      retained.push(senderUserId);
      totalBytes += byteSize;
      if (entry.byteSize !== byteSize || entry.expiresAt !== expiresAt || entry.messageCount !== entry.pendingRequests.length) {
        updates[key] = {
          ...entry,
          byteSize,
          expiresAt,
          messageCount: entry.pendingRequests.length
        };
      }
    }
    updates[this.messageRequestIndexKey()] = retained.sort();
    updates[MESSAGE_REQUEST_META_KEY] = {
      version: 1,
      totalBytes,
      senderCount: retained.length
    };
    await this.state.mutateEntries(updates, deleteKeys);
  }
  async scheduleNextAlarm(now) {
    const meta = await this.getMeta();
    const records = await this.state.list({ prefix: RECORD_PREFIX2 });
    const messageRequestSenders = await this.state.get(this.messageRequestIndexKey()) ?? [];
    let nextAt;
    for (const record of records.values()) {
      if (record.seq > meta.ackedSeq || record.expiresAt === void 0) {
        continue;
      }
      nextAt = nextAt === void 0 ? record.expiresAt : Math.min(nextAt, record.expiresAt);
    }
    for (const senderUserId of messageRequestSenders) {
      const entry = await this.state.get(this.messageRequestKey(senderUserId));
      if (entry?.expiresAt !== void 0) {
        nextAt = nextAt === void 0 ? entry.expiresAt : Math.min(nextAt, entry.expiresAt);
      }
    }
    if (nextAt !== void 0) {
      await this.state.setAlarm(Math.max(now + 1, nextAt));
    }
  }
  toMessageRequestItem(entry) {
    const groupInvite = this.groupInviteMetadata(entry);
    return {
      requestId: entry.requestId,
      recipientDeviceId: entry.recipientDeviceId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      firstSeenAt: entry.firstSeenAt,
      lastSeenAt: entry.lastSeenAt,
      messageCount: entry.messageCount,
      lastMessageId: entry.lastMessageId,
      lastConversationId: entry.lastConversationId,
      requestKind: groupInvite ? "group_invite" : "direct",
      groupId: groupInvite?.groupId,
      groupTitle: groupInvite?.title
    };
  }
  groupInviteMetadata(entry) {
    for (let index = entry.pendingRequests.length - 1; index >= 0; index -= 1) {
      const request = entry.pendingRequests[index];
      if (request.envelope.messageType !== "control_group_welcome_pickup") {
        continue;
      }
      const encoded = request.envelope.inlineCiphertext;
      if (!encoded) {
        return null;
      }
      try {
        const payload = JSON.parse(atob(encoded));
        if (payload.groupId && payload.title) {
          return payload;
        }
      } catch {
        return null;
      }
    }
    return null;
  }
};

// src/inbox/durable.ts
var DurableObjectStorageAdapter2 = class {
  storage;
  constructor(storage) {
    this.storage = storage;
  }
  async get(key) {
    return await this.storage.get(key) ?? void 0;
  }
  async put(key, value) {
    await this.storage.put(key, value);
  }
  async putEntries(entries) {
    await this.storage.put(entries);
  }
  async mutateEntries(entries, deleteKeys) {
    await this.storage.transaction(async (transaction) => {
      if (Object.keys(entries).length > 0) {
        await transaction.put(entries);
      }
      if (deleteKeys.length > 0) {
        await transaction.delete(deleteKeys);
      }
    });
  }
  async delete(key) {
    await this.storage.delete(key);
  }
  async list(options) {
    return this.storage.list(options);
  }
  async setAlarm(epochMillis) {
    await this.storage.setAlarm(epochMillis);
  }
  async consumeIfEqual(key, expected) {
    return this.storage.transaction(async (transaction) => {
      const current = await transaction.get(key);
      if (!current || JSON.stringify(current) !== JSON.stringify(expected)) return false;
      await transaction.delete(key);
      return true;
    });
  }
};
var R2JsonBlobStore2 = class {
  bucket;
  constructor(bucket) {
    this.bucket = bucket;
  }
  async putJson(key, value) {
    await this.bucket.put(key, JSON.stringify(value));
  }
  async getJson(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return await object.json();
  }
  async putBytes(key, value) {
    await this.bucket.put(key, value);
  }
  async getBytes(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return object.arrayBuffer();
  }
  async delete(key) {
    await this.bucket.delete(key);
  }
};
function versionedBody2(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return body;
  }
  const record = body;
  if (record.version !== void 0) {
    return body;
  }
  return {
    version: "0.1",
    ...record
  };
}
function jsonResponse3(body, status = 200, headers) {
  return new Response(JSON.stringify(versionedBody2(body)), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers
    }
  });
}
var DurableObjectBase3 = globalThis.DurableObject ?? class {
  constructor(_state, _env) {
  }
};
async function handleInboxDurableRequest(request, deps) {
  const now = deps.now ?? Date.now();
  const url = new URL(request.url);
  const service = new InboxService(deps.deviceId, deps.state, deps.spillStore, deps.sessions, {
    headSeq: 0,
    ackedSeq: 0,
    retentionDays: deps.retentionDays,
    maxInlineBytes: deps.maxInlineBytes,
    rateLimitPerMinute: deps.rateLimitPerMinute,
    rateLimitPerHour: deps.rateLimitPerHour,
    messageRequestMaxPerSender: deps.messageRequestMaxPerSender ?? 16,
    messageRequestMaxSenders: deps.messageRequestMaxSenders ?? 64,
    messageRequestMaxTotalBytes: deps.messageRequestMaxTotalBytes ?? 4 * 1024 * 1024,
    messageRequestTtlSeconds: deps.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60,
    messageRequestRateLimitMinute: deps.messageRequestRateLimitMinute ?? 30,
    messageRequestRateLimitHour: deps.messageRequestRateLimitHour ?? 300
  });
  try {
    if (url.pathname.endsWith("/subscribe")) {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        throw new HttpError(400, "invalid_input", "subscribe requires websocket upgrade");
      }
      if (!deps.onUpgrade) {
        throw new HttpError(500, "temporary_unavailable", "websocket upgrade handler is unavailable");
      }
      return deps.onUpgrade();
    }
    if (url.pathname.endsWith("/message-requests") && request.method === "GET") {
      return jsonResponse3({ requests: await service.listMessageRequests(now) });
    }
    const requestActionMatch = url.pathname.match(/\/message-requests\/([^/]+)\/(accept|reject)$/);
    if (requestActionMatch && request.method === "POST") {
      const requestId = decodeURIComponent(requestActionMatch[1]);
      const action = requestActionMatch[2];
      const result = action === "accept" ? await service.acceptMessageRequest(requestId, now) : await service.rejectMessageRequest(requestId, now);
      return jsonResponse3(result);
    }
    if (url.pathname.endsWith("/allowlist") && request.method === "GET") {
      return jsonResponse3(await service.getAllowlist(now));
    }
    if (url.pathname.endsWith("/allowlist") && request.method === "PUT") {
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      const result = await service.replaceAllowlist(
        body.allowedSenderUserIds ?? [],
        body.rejectedSenderUserIds ?? [],
        now
      );
      return jsonResponse3(result);
    }
    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = await readJsonLimited(
        request,
        deps.messageRequestMaxBodyBytes ?? DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES
      );
      const mode = request.headers.get(APPEND_AUTH_CONTEXT_HEADER) === "legacy_unverified" ? "legacy_unverified" : "verified";
      const result = await service.appendEnvelope(body, now, {
        mode,
        reason: request.headers.get(APPEND_AUTH_REASON_HEADER) ?? void 0
      });
      return jsonResponse3(result);
    }
    if (url.pathname.endsWith("/messages") && request.method === "GET") {
      const fromSeq = Number(url.searchParams.get("fromSeq") ?? "1");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const result = await service.fetchMessages({
        deviceId: deps.deviceId,
        fromSeq,
        limit
      });
      return jsonResponse3({
        toSeq: result.toSeq,
        records: result.records
      });
    }
    if (url.pathname.endsWith("/ack") && request.method === "POST") {
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      const result = await service.ack(body);
      return jsonResponse3({
        accepted: result.accepted,
        ackSeq: result.ackSeq
      });
    }
    if (url.pathname.endsWith("/head") && request.method === "GET") {
      const result = await service.getHead();
      return jsonResponse3(result);
    }
    return jsonResponse3({ error: "not_found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      const retryAfter = error.details?.retryAfterSeconds;
      return jsonResponse3(
        { error: error.code, message: error.message },
        error.status,
        typeof retryAfter === "number" ? { "Retry-After": String(retryAfter) } : void 0
      );
    }
    const runtimeError = error;
    const message = runtimeError.message ?? "internal error";
    return jsonResponse3({ error: "temporary_unavailable", message }, 500);
  }
}
var InboxDurableObject = class extends DurableObjectBase3 {
  sessions = /* @__PURE__ */ new Map();
  stateRef;
  envRef;
  constructor(state, env) {
    super(state, env);
    this.stateRef = state;
    this.envRef = env;
  }
  async fetch(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(/\/v1\/inbox\/([^/]+)\//);
    const deviceId = decodeURIComponent(match?.[1] ?? "");
    return handleInboxDurableRequest(request, {
      deviceId,
      state: new DurableObjectStorageAdapter2(this.stateRef.storage),
      spillStore: new R2JsonBlobStore2(this.envRef.TAPCHAT_STORAGE),
      sessions: Array.from(this.sessions.values()).map(
        (session) => ({
          send(payload) {
            return session.send(payload);
          }
        })
      ),
      maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096"),
      retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"),
      rateLimitPerMinute: Number(this.envRef.RATE_LIMIT_PER_MINUTE ?? "60"),
      rateLimitPerHour: Number(this.envRef.RATE_LIMIT_PER_HOUR ?? "600"),
      messageRequestMaxBodyBytes: Number(this.envRef.MESSAGE_REQUEST_MAX_BODY_BYTES ?? String(DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES)),
      messageRequestMaxPerSender: Number(this.envRef.MESSAGE_REQUEST_MAX_PER_SENDER ?? "16"),
      messageRequestMaxSenders: Number(this.envRef.MESSAGE_REQUEST_MAX_SENDERS ?? "64"),
      messageRequestMaxTotalBytes: Number(this.envRef.MESSAGE_REQUEST_MAX_TOTAL_BYTES ?? String(4 * 1024 * 1024)),
      messageRequestTtlSeconds: Number(this.envRef.MESSAGE_REQUEST_TTL_SECONDS ?? String(7 * 24 * 60 * 60)),
      messageRequestRateLimitMinute: Number(this.envRef.MESSAGE_REQUEST_RATE_LIMIT_MINUTE ?? "30"),
      messageRequestRateLimitHour: Number(this.envRef.MESSAGE_REQUEST_RATE_LIMIT_HOUR ?? "300"),
      onUpgrade: () => {
        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        server.accept();
        const sessionId = crypto.randomUUID();
        const removeSession = () => {
          this.sessions.delete(sessionId);
        };
        const session = new ManagedSession2(server, removeSession);
        this.sessions.set(sessionId, session);
        server.addEventListener("close", () => {
          session.terminate();
        });
        server.addEventListener("error", (event) => {
          event.preventDefault();
          session.terminate();
        });
        return new Response(null, {
          status: 101,
          webSocket: client
        });
      }
    });
  }
  async alarm() {
    const service = new InboxService(
      "",
      new DurableObjectStorageAdapter2(this.stateRef.storage),
      new R2JsonBlobStore2(this.envRef.TAPCHAT_STORAGE),
      [],
      {
        headSeq: 0,
        ackedSeq: 0,
        retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"),
        maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096"),
        rateLimitPerMinute: Number(this.envRef.RATE_LIMIT_PER_MINUTE ?? "60"),
        rateLimitPerHour: Number(this.envRef.RATE_LIMIT_PER_HOUR ?? "600"),
        messageRequestMaxPerSender: Number(this.envRef.MESSAGE_REQUEST_MAX_PER_SENDER ?? "16"),
        messageRequestMaxSenders: Number(this.envRef.MESSAGE_REQUEST_MAX_SENDERS ?? "64"),
        messageRequestMaxTotalBytes: Number(this.envRef.MESSAGE_REQUEST_MAX_TOTAL_BYTES ?? String(4 * 1024 * 1024)),
        messageRequestTtlSeconds: Number(this.envRef.MESSAGE_REQUEST_TTL_SECONDS ?? String(7 * 24 * 60 * 60)),
        messageRequestRateLimitMinute: Number(this.envRef.MESSAGE_REQUEST_RATE_LIMIT_MINUTE ?? "30"),
        messageRequestRateLimitHour: Number(this.envRef.MESSAGE_REQUEST_RATE_LIMIT_HOUR ?? "300")
      }
    );
    await service.cleanExpiredRecords(Date.now());
  }
};
var ManagedSession2 = class {
  socket;
  onClosed;
  closed = false;
  constructor(socket, onClosed) {
    this.socket = socket;
    this.onClosed = onClosed;
  }
  send(payload) {
    if (this.closed) {
      return false;
    }
    if (this.socket.readyState !== 1) {
      this.finish(false);
      return false;
    }
    try {
      this.socket.send(payload);
      return true;
    } catch {
      this.close();
      return false;
    }
  }
  close() {
    this.finish(true);
  }
  terminate() {
    this.finish(false);
  }
  finish(closeSocket) {
    if (this.closed) {
      return;
    }
    this.closed = true;
    if (closeSocket) {
      try {
        this.socket.close(1011, "session closed");
      } catch {
      }
    }
    this.onClosed();
  }
};

// src/storage/shared-state.ts
function sanitizeSegment(value) {
  return value.replace(/[^a-zA-Z0-9:_-]/g, "_");
}
var SharedStateService = class {
  store;
  baseUrl;
  constructor(store, baseUrl2) {
    this.store = store;
    this.baseUrl = baseUrl2;
  }
  identityBundleKey(userId) {
    return `shared-state/${sanitizeSegment(userId)}/identity_bundle.json`;
  }
  deviceListKey(userId) {
    return `shared-state/${sanitizeSegment(userId)}/device_list.json`;
  }
  deviceStatusKey(userId) {
    return `shared-state/${sanitizeSegment(userId)}/device_status.json`;
  }
  keyPackageRefsKey(userId, deviceId) {
    return `keypackages/${sanitizeSegment(userId)}/${sanitizeSegment(deviceId)}/refs.json`;
  }
  keyPackageObjectKey(userId, deviceId, keyPackageId) {
    return `keypackages/${sanitizeSegment(userId)}/${sanitizeSegment(deviceId)}/${sanitizeSegment(keyPackageId)}.bin`;
  }
  identityBundleUrl(userId) {
    return `${this.baseUrl}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`;
  }
  deviceStatusUrl(userId) {
    return `${this.baseUrl}/v1/shared-state/${encodeURIComponent(userId)}/device-status`;
  }
  keyPackageRefsUrl(userId, deviceId) {
    return `${this.baseUrl}/v1/shared-state/keypackages/${encodeURIComponent(userId)}/${encodeURIComponent(deviceId)}`;
  }
  keyPackageObjectUrl(userId, deviceId, keyPackageId) {
    return `${this.baseUrl}/v1/shared-state/keypackages/${encodeURIComponent(userId)}/${encodeURIComponent(deviceId)}/${encodeURIComponent(keyPackageId)}`;
  }
  async getIdentityBundle(userId) {
    return this.store.getJson(this.identityBundleKey(userId));
  }
  async putIdentityBundle(userId, bundle) {
    if (bundle.userId !== userId) {
      throw new HttpError(400, "invalid_input", "identity bundle userId does not match request path");
    }
    const normalized = {
      ...bundle,
      identityBundleRef: this.identityBundleUrl(userId),
      deviceStatusRef: bundle.deviceStatusRef ?? this.deviceStatusUrl(userId),
      devices: bundle.devices.map((device) => ({
        ...device,
        keypackageRef: {
          ...device.keypackageRef,
          userId,
          deviceId: device.deviceId,
          ref: device.keypackageRef.ref
        }
      }))
    };
    await this.store.putJson(this.identityBundleKey(userId), normalized);
    await this.store.putJson(this.deviceListKey(userId), this.buildDeviceListDocument(normalized));
  }
  async getDeviceList(userId) {
    return this.store.getJson(this.deviceListKey(userId));
  }
  async getDeviceStatus(userId) {
    return this.store.getJson(this.deviceStatusKey(userId));
  }
  async putDeviceStatus(userId, document) {
    if (document.userId !== userId) {
      throw new HttpError(400, "invalid_input", "device status userId does not match request path");
    }
    for (const device of document.devices) {
      if (device.userId !== userId) {
        throw new HttpError(400, "invalid_input", "device status entry userId does not match request path");
      }
    }
    await this.store.putJson(this.deviceStatusKey(userId), document);
  }
  async getKeyPackageRefs(userId, deviceId) {
    return this.store.getJson(this.keyPackageRefsKey(userId, deviceId));
  }
  async putKeyPackageRefs(userId, deviceId, document) {
    if (document.userId !== userId || document.deviceId !== deviceId) {
      throw new HttpError(400, "invalid_input", "keypackage refs scope does not match request path");
    }
    for (const entry of document.refs) {
      if (!entry.ref || !entry.ref.startsWith(this.keyPackageRefsUrl(userId, deviceId))) {
        throw new HttpError(400, "invalid_input", "keypackage ref must be a concrete object URL");
      }
    }
    await this.store.putJson(this.keyPackageRefsKey(userId, deviceId), document);
  }
  async putKeyPackageObject(userId, deviceId, keyPackageId, body) {
    await this.store.putBytes(this.keyPackageObjectKey(userId, deviceId, keyPackageId), body, {
      "content-type": "application/octet-stream"
    });
  }
  async getKeyPackageObject(userId, deviceId, keyPackageId) {
    return this.store.getBytes(this.keyPackageObjectKey(userId, deviceId, keyPackageId));
  }
  buildDeviceListDocument(bundle) {
    return {
      version: bundle.version,
      userId: bundle.userId,
      updatedAt: bundle.updatedAt,
      devices: bundle.devices.map((device) => ({
        deviceId: device.deviceId,
        status: device.status
      }))
    };
  }
};

// src/storage/service.ts
var MAX_BLOB_BYTES = 25 * 1024 * 1024 + 1024;
var SHORT_BLOB_TOKEN_TTL_MS = 15 * 60 * 1e3;
var CAPABILITY_METADATA_KEY = "read-capability-sha256";
function sanitizeSegment2(value) {
  return value.replace(/[^a-zA-Z0-9:_-]/g, "_");
}
function requireNonEmpty(value, field) {
  if (!value || value.trim().length === 0) {
    throw new HttpError(400, "invalid_input", `${field} is required`);
  }
  return value;
}
function randomCapability() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function capabilityHash(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}
var StorageService = class {
  store;
  baseUrl;
  secret;
  constructor(store, baseUrl2, secret) {
    this.store = store;
    this.baseUrl = baseUrl2;
    this.secret = secret;
  }
  async prepareUpload(input, owner, now) {
    const taskId = requireNonEmpty(input.taskId, "taskId");
    const conversationId = requireNonEmpty(input.conversationId, "conversationId");
    const messageId = requireNonEmpty(input.messageId, "messageId");
    if (input.variant !== "original" && input.variant !== "preview") {
      throw new HttpError(400, "invalid_input", "variant must be original or preview");
    }
    if (!Number.isSafeInteger(input.sizeBytes) || input.sizeBytes <= 0 || input.sizeBytes > MAX_BLOB_BYTES) {
      throw new HttpError(400, "invalid_input", "sizeBytes is outside supported limits");
    }
    const storageScope = input.storageScope ?? (input.groupId ? "group" : "direct");
    if (storageScope !== "direct" && storageScope !== "group") {
      throw new HttpError(400, "invalid_input", "storageScope is invalid");
    }
    if (storageScope === "group" && (!input.groupId || input.groupId.trim().length === 0)) {
      throw new HttpError(400, "invalid_input", "groupId is required for group storage");
    }
    const blobKey = [
      "blobs",
      input.variant,
      sanitizeSegment2(owner.userId),
      sanitizeSegment2(owner.deviceId),
      storageScope,
      storageScope === "group" ? sanitizeSegment2(input.groupId) : "direct",
      sanitizeSegment2(conversationId),
      `${sanitizeSegment2(messageId)}-${sanitizeSegment2(taskId)}`
    ].join("/");
    const expiresAt = now + SHORT_BLOB_TOKEN_TTL_MS;
    const readCapability = randomCapability();
    const readCapabilityHash = await capabilityHash(readCapability);
    const uploadToken = await signSharingPayload(this.secret, {
      action: "upload",
      blobKey,
      sizeBytes: input.sizeBytes,
      readCapabilityHash,
      expiresAt
    });
    return {
      blobRef: blobKey,
      uploadTarget: `${this.baseUrl}/v1/storage/upload/${encodeURIComponent(blobKey)}?token=${encodeURIComponent(uploadToken)}`,
      uploadHeaders: {
        "content-type": "application/octet-stream"
      },
      readCapability,
      downloadTarget: `${this.baseUrl}/v1/storage/blob/${encodeURIComponent(blobKey)}`,
      expiresAt
    };
  }
  async uploadBlob(blobKey, token, body, contentLength, now) {
    const payload = await this.verifyToken(token, now);
    if (payload.action !== "upload" || payload.blobKey !== blobKey) {
      throw new HttpError(403, "invalid_capability", "upload token is not valid for this blob");
    }
    if (!Number.isSafeInteger(payload.sizeBytes) || contentLength !== payload.sizeBytes) {
      throw new HttpError(400, "invalid_input", "upload body size does not match prepared size");
    }
    if (!payload.readCapabilityHash) {
      throw new HttpError(403, "invalid_capability", "upload token is missing blob capability binding");
    }
    const stored = await this.store.putStream(blobKey, body, {
      [CAPABILITY_METADATA_KEY]: payload.readCapabilityHash,
      "content-type": "application/octet-stream"
    });
    if (stored.size !== payload.sizeBytes) {
      await this.store.delete(blobKey);
      throw new HttpError(400, "invalid_input", "stored upload size does not match prepared size");
    }
  }
  async fetchBlob(blobKey, capability, rangeHeader, includeBody = true) {
    if (!capability) {
      throw new HttpError(403, "invalid_capability", "blob capability cannot be verified");
    }
    const metadata = await this.store.headBytes(blobKey);
    if (!metadata) {
      throw new HttpError(404, "blob_not_found", "blob does not exist");
    }
    const expectedHash = metadata.customMetadata[CAPABILITY_METADATA_KEY];
    const actualHash = await capabilityHash(capability);
    if (!expectedHash || !constantTimeEqual(expectedHash, actualHash)) {
      throw new HttpError(403, "invalid_capability", "blob capability is not valid for this object");
    }
    const range = rangeHeader ? parseRange(rangeHeader, metadata.size) : void 0;
    if (!includeBody) {
      return {
        body: null,
        size: metadata.size,
        contentLength: range?.length ?? metadata.size,
        ...range ? { range } : {},
        ...metadata.httpEtag ? { httpEtag: metadata.httpEtag } : {}
      };
    }
    const object = await this.store.getStream(blobKey, range);
    if (!object) {
      throw new HttpError(404, "blob_not_found", "blob does not exist");
    }
    return {
      body: object.body,
      size: metadata.size,
      contentLength: range?.length ?? metadata.size,
      ...range ? { range } : {},
      ...object.httpEtag ? { httpEtag: object.httpEtag } : metadata.httpEtag ? { httpEtag: metadata.httpEtag } : {}
    };
  }
  async verifyToken(token, now) {
    try {
      return await verifySharingPayload(this.secret, token, now);
    } catch (error) {
      const message = error instanceof Error ? error.message : "invalid sharing token";
      if (message.includes("expired")) {
        throw new HttpError(403, "capability_expired", message);
      }
      throw new HttpError(403, "invalid_capability", message);
    }
  }
};
function parseRange(header, size) {
  const value = header.startsWith("bytes=") ? header.slice("bytes=".length) : "";
  if (!value || value.includes(",") || !Number.isSafeInteger(size) || size <= 0) {
    throw rangeError(size);
  }
  const separator = value.indexOf("-");
  if (separator < 0 || value.indexOf("-", separator + 1) >= 0) {
    throw rangeError(size);
  }
  const startText = value.slice(0, separator);
  const endText = value.slice(separator + 1);
  if (!startText) {
    const suffix = Number(endText);
    if (!Number.isSafeInteger(suffix) || suffix <= 0) throw rangeError(size);
    const length = Math.min(suffix, size);
    return { offset: size - length, length };
  }
  const offset = Number(startText);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= size) throw rangeError(size);
  if (!endText) return { offset, length: size - offset };
  const requestedEnd = Number(endText);
  if (!Number.isSafeInteger(requestedEnd) || requestedEnd < offset) throw rangeError(size);
  const end = Math.min(requestedEnd, size - 1);
  return { offset, length: end - offset + 1 };
}
function rangeError(size) {
  return new HttpError(416, "range_not_satisfiable", "requested byte range is invalid", {
    totalSize: size
  });
}

// src/welcome-pickup/service.ts
function pickupKey(groupId, deviceId, requestId) {
  return `welcome-pickup/${groupId}/${deviceId}/${requestId ?? "unbound"}.json`;
}
var WelcomePickupService = class {
  store;
  constructor(store) {
    this.store = store;
  }
  async put(request, now) {
    this.validateDescriptor(request.descriptor, now);
    if (!request.welcomeB64?.trim()) {
      throw new HttpError(400, "invalid_input", "welcome_b64 must not be empty");
    }
    await this.store.putJson(pickupKey(request.descriptor.groupId, request.descriptor.deviceId, request.descriptor.requestId), {
      descriptor: request.descriptor,
      welcomeB64: request.welcomeB64,
      manifest: request.manifest,
      storedAt: now
    });
    return { accepted: true };
  }
  async fetch(descriptor, now) {
    this.validateDescriptor(descriptor, now);
    const stored = await this.store.getJson(pickupKey(descriptor.groupId, descriptor.deviceId, descriptor.requestId));
    if (!stored) {
      throw new HttpError(404, "not_found", "welcome pickup not found");
    }
    if (stored.descriptor.capability !== descriptor.capability) {
      throw new HttpError(403, "invalid_capability", "welcome pickup capability does not match stored descriptor");
    }
    if (stored.descriptor.expiresAt <= now) {
      await this.store.delete(pickupKey(descriptor.groupId, descriptor.deviceId));
      throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
    }
    return { welcomeB64: stored.welcomeB64, manifest: stored.manifest };
  }
  validateDescriptor(descriptor, now) {
    if (!descriptor.groupId || !descriptor.deviceId || !descriptor.endpoint || !descriptor.capability) {
      throw new HttpError(400, "invalid_input", "welcome pickup descriptor is missing required fields");
    }
    if (descriptor.expiresAt <= now) {
      throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
    }
  }
};

// src/routes/http.ts
function versionedBody3(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return body;
  }
  const record = body;
  if (record.version !== void 0) {
    return body;
  }
  return {
    version: CURRENT_MODEL_VERSION,
    ...record
  };
}
function jsonResponse4(body, status = 200) {
  return new Response(JSON.stringify(versionedBody3(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}
function forwardRequestWithBody(request, body) {
  return new Request(request.url, {
    method: request.method,
    headers: new Headers(request.headers),
    body
  });
}
var R2JsonBlobStore3 = class {
  bucket;
  constructor(bucket) {
    this.bucket = bucket;
  }
  async putJson(key, value) {
    await this.bucket.put(key, JSON.stringify(value));
  }
  async getJson(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return await object.json();
  }
  async putBytes(key, value, metadata) {
    await this.bucket.put(key, value, metadata ? { customMetadata: metadata } : void 0);
  }
  async getBytes(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return object.arrayBuffer();
  }
  async getBytesMetadata(key) {
    const object = await this.bucket.get(key);
    if (!object) return null;
    return {
      bytes: await object.arrayBuffer(),
      customMetadata: object.customMetadata ?? {}
    };
  }
  async putStream(key, value, metadata) {
    const object = await this.bucket.put(
      key,
      value,
      metadata ? { customMetadata: metadata } : void 0
    );
    return { size: object.size };
  }
  async headBytes(key) {
    const object = await this.bucket.head(key);
    if (!object) return null;
    return {
      size: object.size,
      customMetadata: object.customMetadata ?? {},
      ...object.httpEtag ? { httpEtag: object.httpEtag } : {}
    };
  }
  async getStream(key, range) {
    const object = await this.bucket.get(key, range ? { range } : void 0);
    if (!object) return null;
    return {
      body: object.body,
      size: object.size,
      customMetadata: object.customMetadata ?? {},
      ...object.httpEtag ? { httpEtag: object.httpEtag } : {}
    };
  }
  async delete(key) {
    await this.bucket.delete(key);
  }
};
function baseUrl(request, env) {
  return env.PUBLIC_BASE_URL?.trim().replace(/\/+$/, "") ?? new URL(request.url).origin;
}
function sharedStateSecret(env) {
  return requireSharingSecret(env);
}
function deviceRuntimeSecrets(env) {
  return requireDeviceRuntimeSecrets(env);
}
function messageRequestBodyLimit(env) {
  const configured = Number(env.MESSAGE_REQUEST_MAX_BODY_BYTES ?? DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES);
  return Number.isSafeInteger(configured) && configured > 0 ? configured : DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES;
}
function runtimeScopes() {
  return [
    "inbox_read",
    "inbox_ack",
    "inbox_subscribe",
    "inbox_manage",
    "group_authorization_bootstrap",
    "storage_prepare_upload",
    "shared_state_write",
    "keypackage_write"
  ];
}
function runtimeIdentity(env) {
  const runtimeId = env.RUNTIME_ID?.trim();
  const userId = env.OWNER_USER_ID?.trim();
  const userPublicKey = env.OWNER_USER_PUBLIC_KEY?.trim();
  if (!runtimeId || !userId || !userPublicKey) {
    throw new HttpError(503, "runtime_misconfigured", "runtime owner identity is not configured");
  }
  return { runtimeId, userId, userPublicKey };
}
async function issueDeviceRuntimeAuth(env, userId, deviceId, registrationVersion, now) {
  const { runtimeId } = runtimeIdentity(env);
  const expiresAt = now + 24 * 60 * 60 * 1e3;
  const scopes = runtimeScopes();
  const signingKey = deviceRuntimeSecrets(env).current;
  const token = await signSharingPayload(signingKey.secret, {
    version: CURRENT_MODEL_VERSION,
    service: "device_runtime",
    runtimeId,
    userId,
    deviceId,
    scopes,
    issuedAt: now,
    expiresAt,
    registrationVersion,
    ...signingKey.keyId ? { keyId: signingKey.keyId } : {}
  });
  return {
    scheme: "bearer",
    token,
    issuedAt: now,
    expiresAt,
    runtimeId,
    userId,
    deviceId,
    scopes,
    registrationVersion,
    keyId: signingKey.keyId
  };
}
function publicDeploymentBundle(request, env) {
  const { runtimeId } = runtimeIdentity(env);
  return {
    version: CURRENT_MODEL_VERSION,
    runtimeId,
    protocolVersion: 4,
    workerBuildId: env.WORKER_BUILD_ID?.trim() || "tapchat-worker-v4-unknown",
    registrySchemaVersion: 1,
    region: env.DEPLOYMENT_REGION ?? "local",
    inboxHttpEndpoint: baseUrl(request, env),
    inboxWebsocketEndpoint: `${baseUrl(request, env).replace(/^http/i, "ws")}/v1/inbox/{deviceId}/subscribe`,
    storageBaseInfo: {
      baseUrl: baseUrl(request, env),
      bucketHint: "tapchat-storage"
    },
    runtimeConfig: {
      supportedRealtimeKinds: ["websocket"],
      identityBundleRef: `${baseUrl(request, env)}/v1/shared-state/{userId}/identity-bundle`,
      deviceStatusRef: `${baseUrl(request, env)}/v1/shared-state/{userId}/device-status`,
      keypackageRefBase: `${baseUrl(request, env)}/v1/shared-state/keypackages`,
      maxInlineBytes: Number(env.MAX_INLINE_BYTES ?? "4096"),
      features: [
        "generic_sync",
        "attachment_v2",
        "message_requests",
        "allowlist",
        "rate_limit",
        "group_outbox_mvp",
        "welcome_pickup_mvp",
        "short_group_invite",
        "group_member_subscribe",
        "group_authorization_v2",
        "group_membership_fsm_v2",
        "runtime_secret_rotation_v1",
        "device_runtime_refresh_v2",
        "device_registry_v1"
      ]
    }
  };
}
async function validateRegisteredRuntimeAuthorization(request, env, scope, now) {
  const token = await validateAnyDeviceRuntimeAuthorization(request, deviceRuntimeSecrets(env), scope, now);
  if (token.runtimeId !== runtimeIdentity(env).runtimeId) {
    throw new HttpError(403, "runtime_mismatch", "runtime token audience does not match this runtime");
  }
  await assertRegisteredRuntimeToken(env, token);
  return token;
}
async function validateRegisteredRuntimeAuthorizationForDevice(request, env, deviceId, scope, now) {
  const token = await validateDeviceRuntimeAuthorizationForDevice(
    request,
    deviceRuntimeSecrets(env),
    deviceId,
    scope,
    now
  );
  if (token.runtimeId !== runtimeIdentity(env).runtimeId) {
    throw new HttpError(403, "runtime_mismatch", "runtime token audience does not match this runtime");
  }
  await assertRegisteredRuntimeToken(env, token);
  return token;
}
async function authorizeSharedStateWrite(request, env, userId, objectKind, now) {
  try {
    const auth = await validateRegisteredRuntimeAuthorization(request, env, "shared_state_write", now);
    if (auth.userId !== userId) {
      throw new HttpError(403, "invalid_capability", "device runtime token scope does not match request path");
    }
    return;
  } catch (error) {
    if (!(error instanceof HttpError) || error.code === "runtime_auth_expired" || error.code === "device_revoked" || error.code === "runtime_mismatch" || error.code === "enrollment_required") {
      throw error;
    }
  }
  await validateSharedStateWriteAuthorization(request, sharedStateSecret(env), userId, "", objectKind, now);
}
async function handleRequest(request, env) {
  try {
    const url = new URL(request.url);
    const sharingSecret = sharedStateSecret(env);
    const runtimeSecret = deviceRuntimeSecrets(env).current.secret;
    if (env.DEVICE_RUNTIME_SECRET?.trim() && runtimeSecret === sharingSecret) {
      throw new HttpError(503, "runtime_misconfigured", "device runtime secret must use an independent value");
    }
    const store = new StorageService(
      new R2JsonBlobStore3(env.TAPCHAT_STORAGE),
      baseUrl(request, env),
      sharingSecret
    );
    const sharedState = new SharedStateService(new R2JsonBlobStore3(env.TAPCHAT_STORAGE), baseUrl(request, env));
    const welcomePickup = new WelcomePickupService(new R2JsonBlobStore3(env.TAPCHAT_STORAGE));
    const now = Date.now();
    if (request.method === "GET" && url.pathname === "/v1/deployment-bundle") {
      return jsonResponse4(publicDeploymentBundle(request, env));
    }
    if (request.method === "GET" && url.pathname === "/v2/runtime/ready") {
      try {
        return await registryStub(env).fetch(
          new Request("https://device-registry.internal/v2/device-registry/ready")
        );
      } catch {
        return jsonResponse4(
          { error: "temporary_unavailable", message: "device registry is not ready" },
          503
        );
      }
    }
    const contactShareMatch = url.pathname.match(/^\/v1\/contact-share\/([^/]+)$/);
    if (contactShareMatch && request.method === "GET") {
      const token = decodeURIComponent(contactShareMatch[1]);
      const payload = await verifySharingPayload(sharedStateSecret(env), token, now);
      if (payload.service !== "contact_share" || !payload.userId || !payload.shareId) {
        throw new HttpError(403, "invalid_capability", "invalid contact share token");
      }
      const bundle = await sharedState.getIdentityBundle(payload.userId);
      if (!bundle || bundle.bundleShareId !== payload.shareId) {
        return jsonResponse4({ error: "not_found", message: "contact share not found" }, 404);
      }
      return jsonResponse4(bundle);
    }
    if (request.method === "POST" && url.pathname === "/v2/runtime-auth/challenge") {
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const body = JSON.parse(bodyText);
      if (body.purpose !== "enroll" && body.purpose !== "refresh" || !body.userId || !body.deviceId) {
        throw new HttpError(400, "runtime_auth_invalid", "purpose, userId and deviceId are required");
      }
      try {
        return await registryStub(env).fetch(new Request("https://device-registry.internal/v2/device-registry/challenge", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: bodyText
        }));
      } catch {
        return jsonResponse4(
          { error: "temporary_unavailable", message: "device registry is not ready" },
          503
        );
      }
    }
    if (request.method === "POST" && url.pathname === "/v2/runtime-auth/enroll") {
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const proof = JSON.parse(bodyText);
      const deviceId = proof.challenge?.deviceId;
      const userId = proof.challenge?.userId;
      if (!deviceId || !userId) {
        throw new HttpError(400, "runtime_auth_invalid", "enrollment proof scope is required");
      }
      const verified = await registryStub(env).fetch(new Request("https://device-registry.internal/v2/device-registry/enroll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: bodyText
      }));
      if (!verified.ok) return verified;
      const result = await verified.json();
      return jsonResponse4({ runtimeCredential: await issueDeviceRuntimeAuth(env, userId, deviceId, result.registrationVersion, now) });
    }
    if (request.method === "POST" && url.pathname === "/v2/runtime-auth/refresh") {
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const proof = JSON.parse(bodyText);
      const deviceId = proof.challenge?.deviceId;
      const userId = proof.challenge?.userId;
      if (!deviceId || !userId) {
        throw new HttpError(400, "runtime_auth_invalid", "refresh proof scope is required");
      }
      const verified = await registryStub(env).fetch(new Request("https://device-registry.internal/v2/device-registry/refresh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: bodyText
      }));
      if (!verified.ok) return verified;
      const result = await verified.json();
      return jsonResponse4({ runtimeCredential: await issueDeviceRuntimeAuth(env, userId, deviceId, result.registrationVersion, now) });
    }
    const inboxMatch = url.pathname.match(/^\/v1\/inbox\/([^/]+)\/(messages|ack|head|subscribe|allowlist|message-requests(?:\/[^/]+\/(?:accept|reject))?)$/);
    if (inboxMatch) {
      const deviceId = decodeURIComponent(inboxMatch[1]);
      const operation = inboxMatch[2];
      const objectId = env.INBOX.idFromName(deviceId);
      const stub = env.INBOX.get(objectId);
      if (request.method === "POST" && operation === "messages") {
        const bodyText = await readRequestTextLimited(request, messageRequestBodyLimit(env));
        const body = JSON.parse(bodyText);
        const appendAuth = await validateAppendAuthorization(request, deviceId, body, now, sharedState);
        const forwarded = forwardRequestWithBody(request, bodyText);
        forwarded.headers.set(APPEND_AUTH_CONTEXT_HEADER, appendAuth.mode);
        if (appendAuth.reason) {
          forwarded.headers.set(APPEND_AUTH_REASON_HEADER, appendAuth.reason);
        }
        return await stub.fetch(forwarded);
      } else if (request.method === "GET" && (operation === "messages" || operation === "head")) {
        await validateRegisteredRuntimeAuthorizationForDevice(request, env, deviceId, "inbox_read", now);
      } else if (request.method === "POST" && operation === "ack") {
        await validateRegisteredRuntimeAuthorizationForDevice(request, env, deviceId, "inbox_ack", now);
      } else if (operation === "subscribe") {
        await validateRegisteredRuntimeAuthorizationForDevice(request, env, deviceId, "inbox_subscribe", now);
      } else if (operation === "allowlist" || operation === "message-requests" || operation.startsWith("message-requests/")) {
        await validateRegisteredRuntimeAuthorizationForDevice(request, env, deviceId, "inbox_manage", now);
      }
      if (request.method !== "GET" && request.method !== "HEAD") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await stub.fetch(forwardRequestWithBody(request, bodyText));
      }
      return await stub.fetch(request);
    }
    const groupOutboxMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/outbox\/(messages|transitions|head|seal|subscribe)$/);
    if (groupOutboxMatch) {
      const groupId = decodeURIComponent(groupOutboxMatch[1]);
      const operation = groupOutboxMatch[2];
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      const stub = env.GROUP_OUTBOX.get(objectId);
      if (request.method === "POST" && (operation === "messages" || operation === "transitions")) {
        const bodyText = await readRequestTextLimited(request, messageRequestBodyLimit(env));
        return await stub.fetch(forwardRequestWithBody(request, bodyText));
      }
      if (request.method !== "GET" && request.method !== "HEAD") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await stub.fetch(forwardRequestWithBody(request, bodyText));
      }
      return await stub.fetch(request);
    }
    const groupAuthorizationMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/authorization\/bootstrap$/);
    if (groupAuthorizationMatch && request.method === "POST") {
      const groupId = decodeURIComponent(groupAuthorizationMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
    }
    const groupAuthorizationStateMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/authorization\/state$/);
    if (groupAuthorizationStateMatch && request.method === "GET") {
      const groupId = decodeURIComponent(groupAuthorizationStateMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }
    const shortPublicInviteMatch = url.pathname.match(/^\/v1\/group-invite\/([^/]+)\/([^/]+)$/);
    if (shortPublicInviteMatch && request.method === "GET") {
      const groupId = decodeURIComponent(shortPublicInviteMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }
    const publicInviteMatch = url.pathname.match(/^\/v1\/group-invite\/([^/]+)$/);
    if (publicInviteMatch && request.method === "GET") {
      let payload;
      try {
        payload = await verifySharingPayload(
          sharedStateSecret(env),
          decodeURIComponent(publicInviteMatch[1]),
          now
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : "invalid group invite token";
        throw new HttpError(message.includes("expired") ? 403 : 403, message.includes("expired") ? "capability_expired" : "invalid_capability", message);
      }
      if (payload.service !== "group_invite" || !payload.groupId || !payload.inviteId) {
        throw new HttpError(403, "invalid_capability", "group invite token is malformed");
      }
      const objectId = env.GROUP_OUTBOX.idFromName(payload.groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }
    const groupInviteMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/invites(?:\/([^/]+)\/revoke)?$/);
    if (groupInviteMatch && (request.method === "POST" || request.method === "GET" && !groupInviteMatch[2])) {
      const groupId = decodeURIComponent(groupInviteMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      if (request.method === "POST") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
      }
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }
    const joinCollectionMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests$/);
    if (joinCollectionMatch) {
      const groupId = decodeURIComponent(joinCollectionMatch[1]);
      if (request.method === "POST") {
        const token = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "").trim();
        if (!token) {
          throw new HttpError(401, "invalid_capability", "missing group invite bearer token");
        }
        let payload;
        try {
          payload = await verifySharingPayload(sharedStateSecret(env), token, now);
        } catch (error) {
          const message = error instanceof Error ? error.message : "invalid group invite token";
          throw new HttpError(
            message.includes("expired") ? 403 : 403,
            message.includes("expired") ? "capability_expired" : "invalid_capability",
            message
          );
        }
        if (payload.service !== "group_invite" || payload.groupId !== groupId) {
          throw new HttpError(403, "invalid_capability", "group invite token scope does not match request");
        }
      }
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      if (request.method === "POST") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
      }
      return await env.GROUP_OUTBOX.get(objectId).fetch(request);
    }
    const joinDecisionMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests\/([^/]+)\/decision$/);
    if (joinDecisionMatch && request.method === "POST") {
      const groupId = decodeURIComponent(joinDecisionMatch[1]);
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
    }
    const joinLeaseMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests\/([^/]+)\/(claim|complete)$/);
    if (joinLeaseMatch && request.method === "POST") {
      const groupId = decodeURIComponent(joinLeaseMatch[1]);
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
    }
    const joinStatusMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests\/([^/]+)$/);
    if (joinStatusMatch && request.method === "GET") {
      const groupId = decodeURIComponent(joinStatusMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }
    const leaveRequestMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/leave-requests(?:\/([^/]+)\/claim)?$/);
    if (leaveRequestMatch && (request.method === "GET" || request.method === "POST")) {
      const groupId = decodeURIComponent(leaveRequestMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      if (request.method === "POST") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
      }
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }
    const welcomePickupMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/welcome-pickup\/([^/]+)$/);
    if (welcomePickupMatch) {
      const groupId = decodeURIComponent(welcomePickupMatch[1]);
      const deviceId = decodeURIComponent(welcomePickupMatch[2]);
      if (request.method === "PUT") {
        const body = await readJsonLimited(request, messageRequestBodyLimit(env));
        validateWelcomePickupAuthorization(request, groupId, deviceId, body.descriptor, now);
        if (body.descriptor.requestId) {
          const authorized = await env.GROUP_OUTBOX.get(env.GROUP_OUTBOX.idFromName(groupId)).fetch(
            new Request(`${url.origin}/v1/groups/${encodeURIComponent(groupId)}/internal/welcome-authorize`, {
              method: "POST",
              headers: { "Content-Type": "application/json", "X-Tapchat-Internal-Secret": sharingSecret },
              body: JSON.stringify({ deviceId, requestId: body.descriptor.requestId, capability: body.descriptor.capability })
            })
          );
          if (!authorized.ok) throw new HttpError(409, "group_transition_invalid", "welcome upload is not authorized by a committed join transition");
        }
        return jsonResponse4(await welcomePickup.put(body, now));
      }
      if (request.method === "GET") {
        const encoded = request.headers.get("X-Tapchat-Welcome-Pickup");
        if (!encoded) {
          throw new HttpError(401, "invalid_capability", "missing X-Tapchat-Welcome-Pickup header");
        }
        let descriptor;
        try {
          descriptor = JSON.parse(encoded);
        } catch {
          throw new HttpError(400, "invalid_capability", "X-Tapchat-Welcome-Pickup is not valid JSON");
        }
        validateWelcomePickupAuthorization(request, groupId, deviceId, descriptor, now);
        const result = await welcomePickup.fetch(descriptor, now);
        if (descriptor.requestId) {
          const objectId = env.GROUP_OUTBOX.idFromName(groupId);
          const marked = await env.GROUP_OUTBOX.get(objectId).fetch(
            new Request(`${url.origin}/v1/groups/${encodeURIComponent(groupId)}/internal/welcome-claimed`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Tapchat-Internal-Secret": sharingSecret
              },
              body: JSON.stringify({ deviceId, requestId: descriptor.requestId, capability: descriptor.capability })
            })
          );
          if (!marked.ok) {
            throw new HttpError(500, "temporary_unavailable", "failed to finalize joined group state");
          }
        }
        return jsonResponse4(result);
      }
    }
    const identityBundleMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/identity-bundle$/);
    if (identityBundleMatch) {
      const userId = decodeURIComponent(identityBundleMatch[1]);
      if (request.method === "GET") {
        const bundle = await sharedState.getIdentityBundle(userId);
        if (!bundle) {
          return jsonResponse4({ error: "not_found", message: "identity bundle not found" }, 404);
        }
        return jsonResponse4(bundle);
      }
      if (request.method === "PUT") {
        await authorizeSharedStateWrite(request, env, userId, "identity_bundle", now);
        const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
        const synchronized = await registryStub(env).fetch(new Request("https://device-registry.internal/v2/device-registry/sync", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body)
        }));
        if (!synchronized.ok) return synchronized;
        await sharedState.putIdentityBundle(userId, body);
        const saved = await sharedState.getIdentityBundle(userId);
        return jsonResponse4(saved);
      }
    }
    const deviceStatusMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/device-status$/);
    if (deviceStatusMatch) {
      const userId = decodeURIComponent(deviceStatusMatch[1]);
      if (request.method === "GET") {
        const document = await sharedState.getDeviceStatus(userId);
        if (!document) {
          return jsonResponse4({ error: "not_found", message: "device status not found" }, 404);
        }
        return jsonResponse4(document);
      }
      if (request.method === "PUT") {
        await authorizeSharedStateWrite(request, env, userId, "device_status", now);
        const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
        await sharedState.putDeviceStatus(userId, body);
        const saved = await sharedState.getDeviceStatus(userId);
        return jsonResponse4(saved);
      }
    }
    const deviceListMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/device-list$/);
    if (deviceListMatch && request.method === "GET") {
      const userId = decodeURIComponent(deviceListMatch[1]);
      const document = await sharedState.getDeviceList(userId);
      if (!document) {
        return jsonResponse4({ error: "not_found", message: "device list not found" }, 404);
      }
      return jsonResponse4(document);
    }
    const keyPackageRefsMatch = url.pathname.match(/^\/v1\/shared-state\/keypackages\/([^/]+)\/([^/]+)$/);
    if (keyPackageRefsMatch) {
      const userId = decodeURIComponent(keyPackageRefsMatch[1]);
      const deviceId = decodeURIComponent(keyPackageRefsMatch[2]);
      if (request.method === "GET") {
        const document = await sharedState.getKeyPackageRefs(userId, deviceId);
        if (!document) {
          return jsonResponse4({ error: "not_found", message: "keypackage refs not found" }, 404);
        }
        return jsonResponse4(document);
      }
      if (request.method === "PUT") {
        const authorization = await validateKeyPackageWriteAuthorization(
          request,
          deviceRuntimeSecrets(env),
          userId,
          deviceId,
          void 0,
          now,
          sharedStateSecret(env)
        );
        if (authorization.service === "device_runtime") await assertRegisteredRuntimeToken(env, authorization);
        const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
        await sharedState.putKeyPackageRefs(userId, deviceId, body);
        const saved = await sharedState.getKeyPackageRefs(userId, deviceId);
        return jsonResponse4(saved);
      }
    }
    const keyPackageObjectMatch = url.pathname.match(/^\/v1\/shared-state\/keypackages\/([^/]+)\/([^/]+)\/([^/]+)$/);
    if (keyPackageObjectMatch) {
      const userId = decodeURIComponent(keyPackageObjectMatch[1]);
      const deviceId = decodeURIComponent(keyPackageObjectMatch[2]);
      const keyPackageId = decodeURIComponent(keyPackageObjectMatch[3]);
      if (request.method === "GET") {
        const payload = await sharedState.getKeyPackageObject(userId, deviceId, keyPackageId);
        if (!payload) {
          return jsonResponse4({ error: "not_found", message: "keypackage not found" }, 404);
        }
        return new Response(payload, {
          status: 200,
          headers: {
            "content-type": "application/octet-stream"
          }
        });
      }
      if (request.method === "PUT") {
        const authorization = await validateKeyPackageWriteAuthorization(
          request,
          deviceRuntimeSecrets(env),
          userId,
          deviceId,
          keyPackageId,
          now,
          sharedStateSecret(env)
        );
        if (authorization.service === "device_runtime") await assertRegisteredRuntimeToken(env, authorization);
        await sharedState.putKeyPackageObject(userId, deviceId, keyPackageId, await request.arrayBuffer());
        return new Response(null, { status: 204 });
      }
    }
    if (request.method === "POST" && url.pathname === "/v1/storage/prepare-upload") {
      const auth = await validateRegisteredRuntimeAuthorization(request, env, "storage_prepare_upload", now);
      const body = await readJsonLimited(request, CONTROL_JSON_MAX_BYTES);
      const result = await store.prepareUpload(body, { userId: auth.userId, deviceId: auth.deviceId }, now);
      return jsonResponse4(result);
    }
    const uploadMatch = url.pathname.match(/^\/v1\/storage\/upload\/(.+)$/);
    if (request.method === "PUT" && uploadMatch) {
      const blobKey = decodeURIComponent(uploadMatch[1]);
      const token = url.searchParams.get("token");
      if (!token) {
        throw new HttpError(401, "invalid_capability", "missing upload token");
      }
      const contentLengthHeader = request.headers.get("Content-Length");
      const contentLength = contentLengthHeader && /^\d+$/.test(contentLengthHeader) ? Number(contentLengthHeader) : Number.NaN;
      if (!Number.isSafeInteger(contentLength) || contentLength <= 0 || !request.body) {
        throw new HttpError(400, "invalid_input", "valid Content-Length and upload body are required");
      }
      await store.uploadBlob(blobKey, token, request.body, contentLength, now);
      return new Response(null, { status: 204 });
    }
    const blobMatch = url.pathname.match(/^\/v1\/storage\/blob\/(.+)$/);
    if ((request.method === "GET" || request.method === "HEAD") && blobMatch) {
      const blobKey = decodeURIComponent(blobMatch[1]);
      const header = request.headers.get("Authorization")?.trim();
      if (!header?.startsWith("TapChat-Blob ")) {
        throw new HttpError(401, "invalid_capability", "missing blob capability");
      }
      const capability = header.slice("TapChat-Blob ".length).trim();
      const payload = await store.fetchBlob(
        blobKey,
        capability,
        request.headers.get("Range") ?? void 0,
        request.method === "GET"
      );
      const headers = new Headers({
        "content-type": "application/octet-stream",
        "accept-ranges": "bytes",
        "content-length": String(payload.contentLength)
      });
      if (payload.httpEtag) headers.set("etag", payload.httpEtag);
      if (payload.range) {
        headers.set(
          "content-range",
          `bytes ${payload.range.offset}-${payload.range.offset + payload.range.length - 1}/${payload.size}`
        );
      }
      return new Response(payload.body, {
        status: payload.range ? 206 : 200,
        headers
      });
    }
    return jsonResponse4({ error: "not_found", message: "route not found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      const response = jsonResponse4({ error: error.code, message: error.message, ...error.details ? { details: error.details } : {} }, error.status);
      if (error.status === 416 && typeof error.details?.totalSize === "number") {
        response.headers.set("accept-ranges", "bytes");
        response.headers.set("content-range", `bytes */${error.details.totalSize}`);
      }
      return response;
    }
    const runtimeError = error;
    const message = runtimeError.message ?? "internal error";
    return jsonResponse4({ error: "temporary_unavailable", message }, 500);
  }
}

// src/index.ts
function routeFamilyForObservability(rawUrl) {
  let path = "/";
  try {
    path = new URL(rawUrl).pathname;
  } catch {
    return "invalid_url";
  }
  if (path === "/v1/deployment-bundle") return "deployment_bundle";
  if (path.startsWith("/v2/runtime-auth/")) return "runtime_auth";
  if (path.startsWith("/v1/inbox/")) return "inbox";
  if (path.startsWith("/v1/groups/")) return "group_outbox";
  if (path.startsWith("/v1/group-invite/")) return "group_invite";
  if (path.startsWith("/v1/contact-share/")) return "contact_share";
  if (path.startsWith("/v1/shared-state/")) return "shared_state";
  if (path.startsWith("/v1/storage/")) return "storage";
  if (path.startsWith("/v1/welcome-pickup/")) return "welcome_pickup";
  return "unknown";
}
function logServerFailure(request, status) {
  console.error(JSON.stringify({
    event: "worker_request_failed",
    route_family: routeFamilyForObservability(request.url),
    method: request.method,
    status
  }));
}
var index_default = {
  async fetch(request, env) {
    try {
      const response = await handleRequest(request, env);
      if (response.status >= 500) {
        logServerFailure(request, response.status);
      }
      return response;
    } catch (error) {
      console.error(JSON.stringify({
        event: "worker_unhandled_failure",
        route_family: routeFamilyForObservability(request.url),
        method: request.method,
        error_type: error instanceof Error ? error.name : "unknown"
      }));
      logServerFailure(request, 500);
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  }
};
export {
  DeviceRegistryDurableObject,
  GroupOutboxDurableObject,
  InboxDurableObject,
  index_default as default,
  routeFamilyForObservability
};
