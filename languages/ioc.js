/**
 * ITzMeow80 — snippet di esempio in JavaScript
 * Ricerca di IoC (indicatori di compromissione) in log di testo.
 */

"use strict";

/** Pattern sospetti tipici in log di sistema o chat. */
const IOC_PATTERNS = [
  { name: "IPv4 pubblico", regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  { name: "Dominio", regex: /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi },
  { name: "SHA-256", regex: /\b[a-f0-9]{64}\b/gi },
  { name: "URL", regex: /\bhttps?:\/\/[^\s"'<>]+/gi },
  { name: "Powershell sospetto", regex: /powershell[^\n]{0,120}/gi },
  { name: "Base64 lungo", regex: /[A-Za-z0-9+/]{80,}={0,2}/g },
];

/** Estrae tutti gli IoC da un testo, con conteggio per tipo. */
function extractIocs(text) {
  const results = new Map();
  for (const { name, regex } of IOC_PATTERNS) {
    const matches = text.match(regex);
    if (matches) {
      results.set(name, [...new Set(matches)]);
    }
  }
  return results;
}

/** Raggruppa gli IoC per valore, per rilevare ripetizioni sospette. */
function countOccurrences(text, pattern) {
  const counts = new Map();
  let m;
  while ((m = pattern.exec(text)) !== null) {
    const key = m[0].toLowerCase();
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

/** Stampa un report sintetico degli IoC trovati. */
function printReport(logText) {
  const iocs = extractIocs(logText);
  console.log("=== IOC REPORT ===");
  for (const [type, values] of iocs) {
    console.log(`\n[${type}] ${values.length} trovati`);
    for (const v of values.slice(0, 10)) console.log(`  - ${v}`);
  }
  const domains = countOccurrences(logText, IOC_PATTERNS[1].regex);
  const hot = domains.filter(([, c]) => c >= 5);
  if (hot.length) {
    console.log("\n[!] Domini ripetuti (possibile beaconing):");
    for (const [d, c] of hot) console.log(`  - ${d} (${c}x)`);
  }
}

module.exports = { extractIocs, countOccurrences, printReport, IOC_PATTERNS };

// Esempio:
// printReport(require("fs").readFileSync("sample.log", "utf8"));
