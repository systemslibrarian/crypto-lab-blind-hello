/**
 * Where the config comes from, and who could forge it — the authenticity story
 * behind ECH, shown rather than asserted. If an active attacker can substitute
 * the ECHConfig the client trusts, ECH's cryptography runs flawlessly straight
 * into the attacker's hands: a forged-but-accepted config is the ALARM case,
 * not a green one.
 *
 * This is also why retry_configs must ride inside the certificate-authenticated
 * TLS connection to the public name, and why plaintext DNS is not a safe
 * delivery channel for the first config.
 */
import { EchServer, sealEch } from '../ech/ech';
import { chip, el, fieldTable, staleNotice, tableShell } from './dom';
import { onLabInputChange, PUBLIC_NAME, state } from './state';

interface Channel {
  id: 'dns-plaintext' | 'dns-doh' | 'retry-configs';
  label: string;
  carrier: string;
  authenticated: string;
  attackerCanSubstitute: boolean;
  note: string;
}

const CHANNELS: Channel[] = [
  {
    id: 'dns-plaintext',
    label: 'Plaintext DNS (first contact)',
    carrier: 'HTTPS RR over UDP/53',
    authenticated: 'No — unless DNSSEC is validated end to end (rare on the client)',
    attackerCanSubstitute: true,
    note: 'An on-path attacker forges the DNS answer and inserts their own ECHConfig. The client encrypts to the attacker.',
  },
  {
    id: 'dns-doh',
    label: 'Encrypted DNS / DoH (first contact)',
    carrier: 'HTTPS RR inside TLS to the resolver',
    authenticated: 'The channel to the resolver is — the resolver itself is now trusted',
    attackerCanSubstitute: false,
    note: 'An on-path attacker can no longer rewrite the answer. Trust has moved to the resolver, not vanished.',
  },
  {
    id: 'retry-configs',
    label: 'retry_configs (recovery)',
    carrier: 'EncryptedExtensions inside the handshake to the public name',
    authenticated: 'Yes — inside the public name’s certificate-authenticated TLS connection',
    attackerCanSubstitute: false,
    note: 'Delivered only after the server proved it holds the public name’s certificate. An off-path attacker cannot inject it.',
  },
];

export function trustPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', 'aria-labelledby': 'trust-h' });
  panel.append(
    el('h2', { id: 'trust-h' }, 'Whose key did you encrypt to?'),
    el(
      'p',
      { class: 'panel-lede' },
      'ECH’s privacy rests entirely on one assumption: that the ECHConfig you sealed to really belongs to the server. ' +
        'The cryptography cannot check that — HPKE will happily encrypt to any well-formed key. ' +
        'So the question that decides everything is where the config came from and whether that channel was authenticated.',
    ),
  );

  const runBtn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Run the substituted-config attack');
  panel.append(el('div', { class: 'controls' }, runBtn));

  const out = el('div', { class: 'trust-out', role: 'status', 'aria-live': 'polite' });
  panel.append(out);

  // delivery-channel comparison is static reference, always visible
  const table = el('table', { class: 'fieldtable compare' });
  table.append(el('caption', { class: 'sr-only' }, 'ECHConfig delivery channels and whether an active attacker can substitute the config'));
  table.append(
    el(
      'thead',
      {},
      el(
        'tr',
        {},
        el('th', { scope: 'col' }, 'Delivery channel'),
        el('th', { scope: 'col' }, 'Carrier'),
        el('th', { scope: 'col' }, 'Authenticated?'),
        el('th', { scope: 'col' }, 'Attacker can substitute?'),
      ),
    ),
  );
  const tbody = el('tbody');
  for (const c of CHANNELS) {
    tbody.append(
      el(
        'tr',
        {},
        el('th', { scope: 'row' }, c.label),
        el('td', {}, c.carrier),
        el('td', {}, c.authenticated),
        el(
          'td',
          {},
          el('span', { class: `swap-flag swap-${c.attackerCanSubstitute ? 'yes' : 'no'}` }, c.attackerCanSubstitute ? '✗ yes — forgeable' : '✓ no'),
          el('span', { class: 'note swap-note' }, ` ${c.note}`),
        ),
      ),
    );
  }
  table.append(tbody);
  panel.append(
    el('h3', {}, 'The three ways a client gets an ECHConfig'),
    tableShell(table, 'ECHConfig delivery channels comparison'),
  );

  panel.append(
    el(
      'aside',
      { class: 'honesty' },
      el('h3', {}, 'Why retry_configs is safe and plaintext DNS is not'),
      el(
        'p',
        {},
        'retry_configs arrives inside the handshake to the public name — a connection the server authenticated with a certificate for that name. ' +
          'An attacker who cannot present that certificate cannot inject a config there. The first config, over plaintext DNS, has no such proof: ' +
          'anyone on the path can answer the lookup. This is the same circularity as the bootstrap problem, one layer up — the config is only as trustworthy as the channel that delivered it.',
      ),
    ),
  );

  async function run(): Promise<void> {
    runBtn.disabled = true;
    out.replaceChildren(el('p', { class: 'note' }, 'Substituting a config and sealing to it…'));
    try {
      // The attacker's config: same public name and config_id as the honest
      // server, the attacker's own HPKE key. Exactly what a forged plaintext
      // DNS answer would carry.
      const attacker = new EchServer(PUBLIC_NAME, { configId: state.server.config.configId });
      const sealed = await sealEch({ innerServerName: state.hostname, config: attacker.config });
      const stolen = await attacker.accept(sealed.wire);
      // and prove the honest server can't read the same wire
      const honest = await state.server.accept(sealed.wire);

      out.replaceChildren(
        el('h4', {}, 'The client trusted an ECHConfig an attacker supplied, then sealed to it.'),
        fieldTable('Attack setup', [
          ['Public name (unchanged)', PUBLIC_NAME],
          ['config_id (unchanged)', String(attacker.config.configId)],
          ['HPKE key', 'the ATTACKER’s — the one substituted byte-difference that matters'],
        ]),
        chip('fact', 'HPKE seal (client):', 'succeeded — the client cannot tell one well-formed key from another'),
        chip('fact', 'HPKE open (attacker):', stolen.hpkeOpen === 'ok' ? `succeeded — real decryption` : stolen.hpkeOpen),
        chip(
          'alarm',
          'SECURITY VERDICT: DISCLOSURE',
          `the attacker read your destination “${stolen.innerSni}”. Valid cryptography, wrong recipient — this is the forged-but-accepted case, and it reads as ALARM, not success.`,
        ),
        chip('fact', 'Honest server, same wire:', honest.hpkeOpen === 'fail' ? 'cannot decrypt it (it never held that key)' : honest.hpkeOpen),
        el(
          'p',
          { class: 'note' },
          'Precisely scoped: this is not a break of HPKE or of ECH’s construction — both did exactly what they promise. ' +
            'It is a break of the trust in the delivery channel. Change the channel (rows above) and the same attacker gets nothing.',
        ),
      );
    } finally {
      runBtn.disabled = false;
    }
  }

  // The substitution verdict is a claim about one destination, sealed to one
  // attacker-supplied config, checked against one honest server key. Rotate the
  // key or pick another destination and it describes neither run: the honest
  // server would now fail to open that ClientHello for a reason that has
  // nothing to do with the swap this panel exists to demonstrate. Retire it
  // rather than leave it to be read as current.
  onLabInputChange(() => {
    if (!out.firstChild) return;
    out.replaceChildren(
      staleNotice(
        'this substitution result',
        'Run the substitution again to see it for the current inputs.',
      ),
    );
  });

  runBtn.addEventListener('click', () => void run());
  return panel;
}
