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

export function onHostnameChange(fn: Listener): void {
  listeners.push(fn);
}

export function setHostname(name: string): void {
  state.hostname = name;
  for (const fn of listeners) fn();
}
