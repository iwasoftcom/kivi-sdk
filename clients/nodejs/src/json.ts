// parseJson — a DEPENDENCY-FREE, int64-safe JSON parser for the Node.js SDK.
//
// Node's own JSON.parse() is free (a language builtin, not a package) but
// silently rounds any integer past Number.MAX_SAFE_INTEGER (2^53-1) through
// an IEEE-754 double — exactly the precision loss conformance S2 exists to
// catch (see verify.ts's own comment on the same risk, for the same reason
// the hash-verification scanner splices bytes instead of re-parsing).
//
// object -> Record<string, unknown> (insertion order preserved — the server
// already sends keys sorted), array -> unknown[], string -> string,
// true/false -> boolean, null -> null. A number that fits in a safe integer
// or is a float parses as a plain `number`; a number that would lose
// precision as a `number` parses as a `bigint` instead — never silently
// rounded.
export function parseJson(text: string): unknown {
  const p = new Parser(text);
  const v = p.parseValue();
  p.skipWs();
  if (!p.atEnd()) {
    throw new Error(`trailing data after JSON value at ${p.i}`);
  }
  return v;
}

class Parser {
  s: string;
  i = 0;

  constructor(s: string) {
    this.s = s;
  }

  atEnd(): boolean {
    return this.i >= this.s.length;
  }

  skipWs(): void {
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.i++;
      else break;
    }
  }

  parseValue(): unknown {
    this.skipWs();
    if (this.i >= this.s.length) throw new Error("unexpected end of JSON");
    const c = this.s[this.i];
    if (c === "{") return this.parseObject();
    if (c === "[") return this.parseArray();
    if (c === '"') return this.parseString();
    if (this.s.startsWith("true", this.i)) {
      this.i += 4;
      return true;
    }
    if (this.s.startsWith("false", this.i)) {
      this.i += 5;
      return false;
    }
    if (this.s.startsWith("null", this.i)) {
      this.i += 4;
      return null;
    }
    return this.parseNumber();
  }

  parseObject(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    this.i++; // '{'
    this.skipWs();
    if (this.i < this.s.length && this.s[this.i] === "}") {
      this.i++;
      return out;
    }
    for (;;) {
      this.skipWs();
      const key = this.parseString();
      this.skipWs();
      if (this.i >= this.s.length || this.s[this.i] !== ":") {
        throw new Error(`expected ':' at ${this.i}`);
      }
      this.i++;
      out[key] = this.parseValue();
      this.skipWs();
      if (this.i < this.s.length && this.s[this.i] === ",") {
        this.i++;
        continue;
      }
      if (this.i >= this.s.length || this.s[this.i] !== "}") {
        throw new Error(`expected '}' at ${this.i}`);
      }
      this.i++;
      return out;
    }
  }

  parseArray(): unknown[] {
    const out: unknown[] = [];
    this.i++; // '['
    this.skipWs();
    if (this.i < this.s.length && this.s[this.i] === "]") {
      this.i++;
      return out;
    }
    for (;;) {
      out.push(this.parseValue());
      this.skipWs();
      if (this.i < this.s.length && this.s[this.i] === ",") {
        this.i++;
        continue;
      }
      if (this.i >= this.s.length || this.s[this.i] !== "]") {
        throw new Error(`expected ']' at ${this.i}`);
      }
      this.i++;
      return out;
    }
  }

  parseString(): string {
    if (this.i >= this.s.length || this.s[this.i] !== '"') {
      throw new Error(`expected string at ${this.i}`);
    }
    this.i++;
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) throw new Error("unterminated string");
      const c = this.s[this.i];
      if (c === '"') {
        this.i++;
        return out;
      }
      if (c === "\\") {
        this.i++;
        if (this.i >= this.s.length) throw new Error("unterminated escape");
        const e = this.s[this.i];
        switch (e) {
          case '"':
            out += '"';
            break;
          case "\\":
            out += "\\";
            break;
          case "/":
            out += "/";
            break;
          case "b":
            out += "\b";
            break;
          case "f":
            out += "\f";
            break;
          case "n":
            out += "\n";
            break;
          case "r":
            out += "\r";
            break;
          case "t":
            out += "\t";
            break;
          case "u": {
            const hex = this.s.slice(this.i + 1, this.i + 5);
            out += String.fromCharCode(parseInt(hex, 16));
            this.i += 4;
            break;
          }
          default:
            throw new Error(`bad escape \\${e}`);
        }
        this.i++;
      } else {
        out += c;
        this.i++;
      }
    }
  }

  parseNumber(): number | bigint {
    const start = this.i;
    if (this.i < this.s.length && (this.s[this.i] === "-" || this.s[this.i] === "+")) this.i++;
    while (this.i < this.s.length && this.isDigit(this.s[this.i])) this.i++;
    let isFloat = false;
    if (this.i < this.s.length && this.s[this.i] === ".") {
      isFloat = true;
      this.i++;
      while (this.i < this.s.length && this.isDigit(this.s[this.i])) this.i++;
    }
    if (this.i < this.s.length && (this.s[this.i] === "e" || this.s[this.i] === "E")) {
      isFloat = true;
      this.i++;
      if (this.i < this.s.length && (this.s[this.i] === "+" || this.s[this.i] === "-")) this.i++;
      while (this.i < this.s.length && this.isDigit(this.s[this.i])) this.i++;
    }
    const tok = this.s.slice(start, this.i);
    if (tok === "" || tok === "-" || tok === "+") {
      throw new Error(`invalid number at ${start}`);
    }
    if (!isFloat) {
      const big = BigInt(tok);
      // safe as a plain `number` only if round-tripping through BigInt loses
      // nothing — otherwise keep it a BigInt rather than silently rounding
      if (big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER)) {
        return Number(big);
      }
      return big;
    }
    return Number(tok);
  }

  private isDigit(c: string): boolean {
    return c >= "0" && c <= "9";
  }
}
