/** Deployment honesty — the facts, no editorializing, plus the scope inventory. */
import { el } from './dom';
import { LABS } from './links';

export function deploymentPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', 'aria-labelledby': 'deploy-h' });
  panel.append(
    el('h2', { id: 'deploy-h' }, 'Where ECH actually stands'),
    el(
      'ul',
      { class: 'facts', role: 'list' },
      el('li', { role: 'listitem' }, 'ECH is an IETF draft (draft-ietf-tls-esni), not yet an RFC. Its predecessor, ESNI, was abandoned after deployment experience.'),
      el('li', { role: 'listitem' }, 'It is deployed at scale anyway: Cloudflare enables it across free zones; Firefox (118+) supports it when DoH is enabled; Chrome (117+) rolled it out with its built-in secure-DNS support.'),
      el('li', { role: 'listitem' }, 'Some networks block or strip it. China’s national firewall has blocked ESNI-bearing TLS since 2020; Russian authorities have moved to restrict TLS-hiding technologies including ECH. Enterprise middleboxes that filter by SNI cannot see through it, and some drop it.'),
      el('li', { role: 'listitem' }, 'Browsers therefore ship fallbacks: when an ECH connection is interfered with, clients may retry without it — availability is chosen over privacy at that boundary.'),
      el('li', { role: 'listitem' }, 'ECH hides which site you reached only within the set of sites behind the same provider. A site alone on its own IP address is identified by the address itself; no ClientHello field changes that.'),
      el('li', { role: 'listitem' }, 'ECH does not hide packet sizes, timing, or traffic patterns. Fingerprinting attacks on those signals are real and out of this lab’s scope.'),
    ),
    el(
      'aside',
      { class: 'honesty' },
      el('h3', {}, 'What is real here, and what is not'),
      el(
        'ul',
        { role: 'list' },
        el('li', { role: 'listitem' }, el('strong', {}, 'Real:'), ' every HPKE seal/open (RFC 9180, the imported ', el('a', { href: LABS.hpkeEnvelope }, 'HPKE Envelope'), ' implementation, KAT-verified here), the ClientHello / ECHConfig / HTTPS-record byte encodings, the padding, the AAD binding, GREASE, and every failure you trigger.'),
        el('li', { role: 'listitem' }, el('strong', {}, 'Modeled and labelled:'), ' the wire itself (no packets leave this page), the DNS transaction, and the handshake that follows the ClientHello.'),
        el('li', { role: 'listitem' }, el('strong', {}, 'Not proven here:'), ' that ECH resists active attackers who can block traffic (they can force the no-ECH fallback), or traffic-analysis attacks. This page demonstrates what a passive observer of the first packet learns — nothing more.'),
      ),
      el('p', {}, 'Not production crypto — a teaching demo.'),
    ),
    el(
      'p',
      { class: 'note' },
      'What this lab deliberately isn’t: the TLS handshake itself lives in ',
      el('a', { href: LABS.tlsHandshake }, 'tls-handshake'),
      ' (and its post-quantum sibling ',
      el('a', { href: LABS.pqTlsHandshake }, 'pq-tls-handshake'),
      '); HPKE’s internals live in ',
      el('a', { href: LABS.hpkeEnvelope }, 'hpke-envelope'),
      '; hiding metadata from the *server* rather than the network is ',
      el('a', { href: LABS.blindRelay }, 'blind-relay'),
      ' (OHTTP). No DoH/DoT client is implemented here (RFC 8484 / RFC 7858), and no traffic-analysis tooling.',
    ),
  );
  return panel;
}
