/**
 * ITzMeow80 — snippet di esempio in TypeScript
 * Scanner di hash e indicatori (IoC) per file sospetti.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export type Severity = "info" | "suspicious" | "malicious";

export interface ScanResult {
  file: string;
  sha256: string;
  size: number;
  severity: Severity;
  matches: string[];
}

/** Firma minima: sequenza di byte in formato hex. */
interface Signature {
  name: string;
  pattern: number[];
  severity: Severity;
}

const SIGNATURES: Signature[] = [
  { name: "MZ header (PE executable)", pattern: [0x4d, 0x5a], severity: "info" },
  { name: "PE signature", pattern: [0x50, 0x45, 0x00, 0x00], severity: "info" },
  { name: "Indirect call (API resolution)", pattern: [0xff, 0x15], severity: "suspicious" },
  { name: "XOR EAX,EAX (zero-register)", pattern: [0x31, 0xc0], severity: "suspicious" },
];

/** Calcola l'entropia di Shannon di un buffer (packing/criptazione). */
export function shannonEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (const b of data) counts[b]++;
  return counts.reduce((acc, c) => {
    if (c === 0) return acc;
    const p = c / data.length;
    return acc - p * Math.log2(p);
  }, 0);
}

/** Cerca tutte le firme note nel buffer. */
export function matchSignatures(data: Uint8Array): string[] {
  const found: string[] = [];
  for (const sig of SIGNATURES) {
    const len = sig.pattern.length;
    outer: for (let i = 0; i + len <= data.length; i++) {
      for (let j = 0; j < len; j++) {
        if (data[i + j] !== sig.pattern[j]) continue outer;
      }
      found.push(sig.name);
      break outer;
    }
  }
  return found;
}

/** Scansiona un file e restituisce hash, entropia e firme trovate. */
export async function scanFile(file: string): Promise<ScanResult> {
  const data = await readFile(file);
  const matches = matchSignatures(data);
  const entropy = shannonEntropy(data);

  let severity: Severity = "info";
  if (entropy > 7.2 && matches.some((m) => m.includes("PE"))) severity = "malicious";
  else if (matches.length > 0) severity = "suspicious";

  return {
    file,
    sha256: createHash("sha256").update(data).digest("hex"),
    size: data.length,
    severity,
    matches,
  };
}

// Esempio d'uso:
// const result = await scanFile("suspicious.dll");
// console.log(result.sha256, result.severity, result.matches);
