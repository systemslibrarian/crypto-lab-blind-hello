/**
 * Per-session lab state: one ECH server (fresh X25519 key each page load,
 * in memory only) and the destination the learner picked. Nothing persists.
 */
import { EchServer } from '../ech/ech';

export const PUBLIC_NAME = 'public.cdn.example';
export const SERVER_IP = '203.0.113.10';
export const RESOLVER_IP = '192.0.2.53';

export const PRESET_HOSTS = ['bank.example.com', 'news.example.org', 'clinic.example.net'];

export const state = {
  server: new EchServer(PUBLIC_NAME, { maximumNameLength: 64 }),
  hostname: PRESET_HOSTS[0],
};

type Listener = () => void;
const listeners: Listener[] = [];

/**
 * Every result on this page is computed from two inputs: the destination the
 * learner picked, and the server's current HPKE key. When either changes, a
 * result already on screen describes a run that no longer matches what the
 * controls say — "observer read your destination bank.example.com" sitting
 * under a select that now reads news.example.org, or a swap-attack verdict
 * blaming the AAD binding for a failure the key rotation would have caused
 * anyway. Panels subscribe here and retire their own output rather than leave
 * a stale verdict to be re-read as current.
 */
export function onLabInputChange(fn: Listener): void {
  listeners.push(fn);
}

function notify(): void {
  for (const fn of listeners) fn();
}

export function setHostname(name: string): void {
  if (name === state.hostname) return;
  state.hostname = name;
  notify();
}

/**
 * Rotate the server's HPKE key (the stale-cached-config scenario). Everything
 * already rendered was sealed to, or decrypted with, the previous key — so
 * this is an input change like any other.
 */
export function rotateServerKey(): void {
  state.server.rotateKey();
  notify();
}
