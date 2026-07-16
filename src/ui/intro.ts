/** Plain-language on-ramp + progressive-disclosure jargon scaffold. */
import { el } from './dom';
import { LABS } from './links';

export function introPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', 'aria-labelledby': 'intro-h' });
  panel.append(
    el('h2', { id: 'intro-h' }, 'What is this?'),
    el(
      'p',
      { class: 'panel-lede' },
      'When your browser opens a secure connection, TLS 1.3 encrypts nearly everything — the server’s certificate, every page, every byte after the handshake. ' +
        'But the very first packet has to say which site it wants, in a field called SNI, and that field is plain text. ' +
        'Anyone on the path — a coffee-shop router, an ISP, a national firewall — reads your destination without breaking any cryptography at all. ' +
        'Encrypted Client Hello (ECH) encrypts that one field. This lab shows the leak, the fix, and the honest catches.',
    ),
    el(
      'details',
      { class: 'expert' },
      el('summary', {}, 'The four words you need'),
      el(
        'ul',
        { role: 'list' },
        el('li', { role: 'listitem' }, el('strong', {}, 'SNI'), ' — Server Name Indication: the hostname field in the first TLS packet, there so one IP address can host many sites.'),
        el(
          'li',
          { role: 'listitem' },
          el('strong', {}, 'HPKE'),
          ' — Hybrid Public Key Encryption (RFC 9180): encrypt to someone’s public key. ECH’s entire cryptography is one HPKE seal. It has ',
          el('a', { href: LABS.hpkeEnvelope }, 'its own lab'),
          ', and this demo runs that lab’s implementation.',
        ),
        el('li', { role: 'listitem' }, el('strong', {}, 'ECHConfig'), ' — the server’s public handout (HPKE key, a decoy “public name”), published in DNS, that lets clients encrypt to it.'),
        el('li', { role: 'listitem' }, el('strong', {}, 'AAD'), ' — additional authenticated data: bytes an AEAD cipher doesn’t encrypt but does bind; change them and decryption fails.'),
      ),
    ),
  );
  return panel;
}
