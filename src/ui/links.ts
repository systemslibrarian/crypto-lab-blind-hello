/** Sibling labs this demo links out to instead of rebuilding (scope guard). */
const gh = (repo: string) => `https://systemslibrarian.github.io/${repo}/`;

export const LABS = {
  catalog: 'https://crypto-lab.systemslibrarian.dev/',
  hpkeEnvelope: gh('crypto-lab-hpke-envelope'),
  tlsHandshake: gh('crypto-lab-tls-handshake'),
  pqTlsHandshake: gh('crypto-lab-pq-tls-handshake'),
  blindRelay: gh('crypto-lab-blind-relay'),
  downgradeWire: gh('crypto-lab-downgrade-wire'),
} as const;
