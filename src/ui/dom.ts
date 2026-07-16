/** Small DOM helpers + the packet-dump renderer the observer panels share. */
import type { Span } from '../ech/clienthello';

type Attrs = Record<string, string | boolean | undefined>;
type Child = Node | string | null | undefined;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'text') node.textContent = String(v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.append(c);
  }
  return node;
}

export type ChipKind = 'ok' | 'alarm' | 'warn' | 'fact';

const CHIP_ICON: Record<ChipKind, string> = { ok: '✓', alarm: '✗', warn: '⚠', fact: '·' };

/** State is never color alone: every chip carries icon + words + color. */
export function chip(kind: ChipKind, label: string, text: string): HTMLElement {
  return el(
    'span',
    { class: `chip chip-${kind}` },
    el('span', { class: 'chip-icon', 'aria-hidden': 'true' }, CHIP_ICON[kind]),
    el('strong', {}, label),
    ' ',
    text,
  );
}

export interface HighlightSpan {
  span: Span;
  cls: 'hl-alarm' | 'hl-ok' | 'hl-info';
  label: string;
}

const PRINTABLE_MIN = 0x20;
const PRINTABLE_MAX = 0x7e;

function classAt(offset: number, highlights: HighlightSpan[]): string | undefined {
  for (const h of highlights) {
    if (offset >= h.span.start && offset < h.span.end) return h.cls;
  }
  return undefined;
}

/**
 * A classic hex+ASCII packet dump: 16 bytes per row, offset gutter, printable
 * characters rendered as themselves in the right column — so a cleartext
 * hostname is literally readable in the dump, and a ciphertext is not.
 */
export function hexDump(bytes: Uint8Array, highlights: HighlightSpan[], ariaLabel: string): HTMLElement {
  const pre = el('pre', { class: 'hexdump' });
  for (let row = 0; row < bytes.length; row += 16) {
    const line = el('span', { class: 'hexrow' });
    line.append(el('span', { class: 'hexoff' }, row.toString(16).padStart(4, '0') + '  '));
    // hex column
    for (let i = row; i < row + 16; i++) {
      if (i >= bytes.length) {
        line.append('   ');
        continue;
      }
      const cls = classAt(i, highlights);
      const hex = bytes[i].toString(16).padStart(2, '0');
      line.append(cls ? el('mark', { class: cls }, hex) : hex, ' ');
    }
    line.append(' ');
    // ascii column
    for (let i = row; i < Math.min(row + 16, bytes.length); i++) {
      const b = bytes[i];
      const ch = b >= PRINTABLE_MIN && b <= PRINTABLE_MAX ? String.fromCharCode(b) : '·';
      const cls = classAt(i, highlights);
      line.append(cls ? el('mark', { class: cls }, ch) : ch);
    }
    line.append('\n');
    pre.append(line);
  }
  // scrollable → must be keyboard-reachable and named (WCAG)
  const region = el('div', { class: 'hexdump-region', tabindex: '0', role: 'region', 'aria-label': ariaLabel });
  region.append(pre);
  return region;
}

export function legend(highlights: HighlightSpan[]): HTMLElement {
  const wrap = el('p', { class: 'legend' });
  for (const h of highlights) {
    wrap.append(el('mark', { class: h.cls }, ' '), ` ${h.label}   `);
  }
  return wrap;
}

/** Printable ASCII runs of length ≥ min — what `strings` would grep from the packet. */
export function asciiStrings(bytes: Uint8Array, min = 4): string[] {
  const out: string[] = [];
  let run = '';
  for (const b of bytes) {
    if (b >= PRINTABLE_MIN && b <= PRINTABLE_MAX) {
      run += String.fromCharCode(b);
    } else {
      if (run.length >= min) out.push(run);
      run = '';
    }
  }
  if (run.length >= min) out.push(run);
  return out;
}

export function fieldTable(caption: string, rows: [string, string][]): HTMLElement {
  const table = el('table', { class: 'fieldtable' });
  table.append(el('caption', { class: 'sr-only' }, caption));
  const tbody = el('tbody');
  for (const [k, v] of rows) {
    tbody.append(el('tr', {}, el('th', { scope: 'row' }, k), el('td', {}, v)));
  }
  table.append(tbody);
  return table;
}

export function truncHex(bytes: Uint8Array, keep = 12): string {
  let s = '';
  for (let i = 0; i < Math.min(keep, bytes.length); i++) s += bytes[i].toString(16).padStart(2, '0');
  return bytes.length > keep ? `${s}… (${bytes.length} B)` : s;
}
