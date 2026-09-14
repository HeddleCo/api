/** The bounded MessagePack subset used by Rust's rmp-serde named records.
 * Uint8Array is serde_bytes/UUID binary; number[] is Rust Vec<u8>/[u8; N]. */
export type Value = null | boolean | number | bigint | string | Uint8Array | Value[] | { [key: string]: Value };
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
export const MAX_RECORD_BYTES = 256 * 1024;

export function encode(value: Value): Uint8Array {
  const bytes: number[] = [];
  function uint(value: bigint, size: number) {
    for (let n = size - 1; n >= 0; n--) bytes.push(Number((value >> BigInt(n * 8)) & 255n));
  }
  function length(value: number, fixed: number, max: number, tag8: number | null, tag16: number, tag32: number) {
    if (value <= max) bytes.push(fixed + value);
    else if (tag8 !== null && value <= 255) bytes.push(tag8, value);
    else if (value <= 65535) { bytes.push(tag16); uint(BigInt(value), 2); }
    else { bytes.push(tag32); uint(BigInt(value), 4); }
  }
  function put(value: Value, depth: number) {
    if (depth > 32 || bytes.length > MAX_RECORD_BYTES) throw new Error("Collaboration record exceeds encoding bounds");
    if (value === null) bytes.push(0xc0);
    else if (typeof value === "boolean") bytes.push(value ? 0xc3 : 0xc2);
    else if (typeof value === "number" || typeof value === "bigint") {
      if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("MessagePack requires an exact integer");
      const n = BigInt(value);
      if (n >= 0n) {
        if (n <= 127n) bytes.push(Number(n));
        else if (n <= 255n) { bytes.push(0xcc); uint(n, 1); }
        else if (n <= 65535n) { bytes.push(0xcd); uint(n, 2); }
        else if (n <= 4294967295n) { bytes.push(0xce); uint(n, 4); }
        else if (n <= 18446744073709551615n) { bytes.push(0xcf); uint(n, 8); }
        else throw new Error("MessagePack integer exceeds uint64");
      } else if (n >= -32n) bytes.push(Number(256n + n));
      else if (n >= -128n) { bytes.push(0xd0); uint(n, 1); }
      else if (n >= -32768n) { bytes.push(0xd1); uint(n, 2); }
      else if (n >= -2147483648n) { bytes.push(0xd2); uint(n, 4); }
      else if (n >= -9223372036854775808n) { bytes.push(0xd3); uint(n, 8); }
      else throw new Error("MessagePack integer exceeds int64");
    } else if (typeof value === "string") {
      const utf8 = encoder.encode(value);
      length(utf8.length, 0xa0, 31, 0xd9, 0xda, 0xdb);
      for (const byte of utf8) bytes.push(byte);
    } else if (value instanceof Uint8Array) {
      length(value.length, 0, -1, 0xc4, 0xc5, 0xc6);
      for (const byte of value) bytes.push(byte);
    } else if (Array.isArray(value)) {
      length(value.length, 0x90, 15, null, 0xdc, 0xdd);
      for (const item of value) put(item, depth + 1);
    } else {
      const entries = Object.entries(value);
      length(entries.length, 0x80, 15, null, 0xde, 0xdf);
      for (const [key, item] of entries) { put(key, depth + 1); put(item, depth + 1); }
    }
  }
  put(value, 0);
  if (bytes.length > MAX_RECORD_BYTES) throw new Error("Collaboration record exceeds encoding bounds");
  return Uint8Array.from(bytes);
}

export function decode(bytes: Uint8Array): Value {
  if (bytes.length > MAX_RECORD_BYTES) throw new Error("Collaboration record exceeds decoding bounds");
  let offset = 0;
  function take(n: number): Uint8Array {
    if (n > bytes.length - offset) throw new Error("Truncated collaboration MessagePack");
    const value = bytes.slice(offset, offset + n); offset += n; return value;
  }
  function int(size: number, signed = false): bigint {
    const bytes = take(size); let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (signed && bytes[0]! >= 128) value -= 1n << BigInt(size * 8);
    return value;
  }
  function integer(size: number, signed = false): number | bigint {
    const value = int(size, signed);
    return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
  }
  function array(n: number, depth: number): Value[] {
    if (n > bytes.length - offset) throw new Error("Invalid MessagePack array length");
    return Array.from({ length: n }, () => get(depth + 1));
  }
  function map(n: number, depth: number): Value {
    if (n > (bytes.length - offset) / 2) throw new Error("Invalid MessagePack map length");
    const value: { [key: string]: Value } = Object.create(null);
    for (let i = 0; i < n; i++) {
      const key = get(depth + 1);
      if (typeof key !== "string" || Object.hasOwn(value, key)) throw new Error("Invalid or duplicate MessagePack key");
      value[key] = get(depth + 1);
    }
    return value;
  }
  function get(depth: number): Value {
    if (depth > 32) throw new Error("Collaboration MessagePack nesting exceeds bound");
    const tag = take(1)[0]!;
    if (tag <= 127) return tag;
    if (tag >= 224) return tag - 256;
    if (tag >= 160 && tag <= 191) return decoder.decode(take(tag - 160));
    if (tag >= 144 && tag <= 159) return array(tag - 144, depth);
    if (tag >= 128 && tag <= 143) return map(tag - 128, depth);
    switch (tag) {
      case 0xc0: return null;
      case 0xc2: return false;
      case 0xc3: return true;
      case 0xcc: return integer(1);
      case 0xcd: return integer(2);
      case 0xce: return integer(4);
      case 0xcf: return integer(8);
      case 0xd0: return integer(1, true);
      case 0xd1: return integer(2, true);
      case 0xd2: return integer(4, true);
      case 0xd3: return integer(8, true);
      case 0xc4: case 0xc5: case 0xc6: return take(Number(int(1 << (tag - 0xc4))));
      case 0xd9: case 0xda: case 0xdb: return decoder.decode(take(Number(int(1 << (tag - 0xd9)))));
      case 0xdc: case 0xdd: return array(Number(int(tag === 0xdc ? 2 : 4)), depth);
      case 0xde: case 0xdf: return map(Number(int(tag === 0xde ? 2 : 4)), depth);
      default: throw new Error("Unsupported collaboration MessagePack type");
    }
  }
  const value = get(0);
  if (offset !== bytes.length) throw new Error("Trailing collaboration MessagePack bytes");
  if (!equal(encode(value), bytes)) throw new Error("Noncanonical collaboration MessagePack");
  return value;
}
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
