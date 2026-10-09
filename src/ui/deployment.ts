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
      el('li', { role: 'listitem' }, 'ECH is standardized in ', el('a', { href: 'https://www.rfc-editor.org/rfc/rfc9849.html' }, 'RFC 9849 (March 2026)'), '. Its predecessor, ESNI, was abandoned after deployment experience.'),
      el('li', { role: 'listitem' }, 'Deployment examples include: Cloudflare enables it across free zones; Firefox (118+) supports it when DoH is enabled; Chrome (117+) rolled it out with its built-in secure-DNS support.'),
      el('li', { role: 'listitem' }, 'Some networks block or strip it. China’s national firewall has blocked ESNI-bearing TLS since 2020; Russian authorities have moved to restrict TLS-hiding technologies including ECH. Enterprise middleboxes that filter by SNI cannot see through it, and some drop it.'),
      el('li', { role: 'listitem' }, 'Blocking traffic can deny availability; it does not authorize disabling ECH. Under ', el('a', { href: 'https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.6' }, 'RFC 9849 §6.1.6'), ', after ECH rejection the client must authenticate the outer handshake for the public name. Authentication or handshake failure must fail the connection; it must not be treated as a secure signal to disable ECH.'),
      el('li', { role: 'listitem' }, 'After successful public-name authentication and handshake completion, the client aborts the rejected connection before sending application data. Supported retry_configs guide a new ECH attempt. If no retry config has a supported version, the server omits the ECH extension in EncryptedExtensions, or an earlier TLS version was negotiated, the authenticated result can securely disable ECH and guide a new connection without it. These signals differ from an arbitrary network blocker.'),
      el('li', { role: 'listitem' }, 'Unauthenticated DNS can let an attacker strip or substitute the ECH configuration before the client attempts ECH; this is a configuration-delivery attack, described in ', el('a', { href: 'https://www.rfc-editor.org/rfc/rfc9849.html#section-10.2' }, 'RFC 9849 §10.2'), '.'),
      el('li', { role: 'listitem' }, 'Managed enterprise policy may disable ECH depending on client implementation and deployment settings (', el('a', { href: 'https://www.rfc-editor.org/rfc/rfc9849.html#section-8.2' }, 'RFC 9849 §8.2'), '). This panel explains protocol requirements, not tested browser fallback behavior.'),
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
        el('li', { role: 'listitem' }, el('strong', {}, 'Not proven here:'), ' full TLS/ECH rejection, public-name authentication, retry or disablement behavior, resistance to availability denial, or traffic-analysis attacks. The configuration-substitution exhibit demonstrates a delivery-channel risk; it does not show that dropping traffic forces a compliant client to reveal the inner name.'),
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
