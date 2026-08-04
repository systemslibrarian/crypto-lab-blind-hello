/**
 * The bootstrap problem — the honest centerpiece. The ECH public key arrives
 * via DNS; a plaintext lookup announces the very name ECH exists to hide.
 * Show the leak, close it, and name the circularity plainly.
 */
import { serializeECHConfigList } from '../ech/echconfig';
import { encodeHttpsRdata, observeDnsLookup, type DnsTransport } from '../dns/httpsrr';
import { chip, el, fieldTable, hexDump, staleNotice } from './dom';
import { onLabInputChange, RESOLVER_IP, state } from './state';

export function dnsPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', 'aria-labelledby': 'dns-h' });
  panel.append(
    el('h2', { id: 'dns-h' }, 'The bootstrap problem — where the key comes from'),
    el(
      'p',
      { class: 'panel-lede' },
      'ECH is not magic: the client can only encrypt to the server’s HPKE key if it has the key. ' +
        'That key travels in the DNS HTTPS record (the ech parameter). So before the first TLS byte, there is a DNS lookup — and the lookup names the destination.',
    ),
    el(
      'p',
      { class: 'note' },
      'The HTTPS-record encoding below is the real RFC 9460 RDATA wire format. The DNS transaction around it is modeled and labelled — this lab implements no resolver and no DoH client.',
    ),
  );

  const fieldset = el('fieldset', { class: 'ctl-radio' });
  fieldset.append(el('legend', {}, 'How does the lookup travel?'));
  const mk = (value: DnsTransport, label: string, checked?: boolean) => {
    const input = el('input', { type: 'radio', name: 'dns-transport', id: `dns-${value}`, value, ...(checked ? { checked: true } : {}) });
    return el('span', { class: 'radio-item' }, input, el('label', { for: `dns-${value}` }, label));
  };
  fieldset.append(mk('plaintext', 'Plaintext DNS (port 53)', true), mk('doh', 'Encrypted DNS (DoH/DoT — modeled)'));
  const lookupBtn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Look up the ECHConfig');
  panel.append(el('div', { class: 'controls' }, fieldset, lookupBtn));

  const out = el('div', { class: 'dns-out', role: 'status', 'aria-live': 'polite' });
  panel.append(out);

  panel.append(
    el(
      'aside',
      { class: 'honesty' },
      el('h3', {}, 'The circularity, named'),
      el(
        'p',
        {},
        'ECH hides the hostname inside TLS. The key that makes that possible arrives over DNS. Plaintext DNS announces the hostname. ' +
          'So ECH only means something when the DNS lookup is itself encrypted (DoH/DoT) — encrypting the lookup that exists to encrypt the hello. ' +
          'Deployed ECH accepts this: Firefox, for example, only enables ECH when DoH is on. There is no trick that removes the dependency; there is only moving the trust to the resolver.',
      ),
    ),
  );

  function run(): void {
    const transport = (panel.querySelector('input[name="dns-transport"]:checked') as HTMLInputElement).value as DnsTransport;
    const host = state.hostname;
    const rdata = encodeHttpsRdata({
      priority: 1,
      targetName: '.',
      alpn: ['h2'],
      echConfigList: serializeECHConfigList([state.server.config]),
    });
    const obs = observeDnsLookup(host, transport, RESOLVER_IP);

    const obsList = el('ul', { class: 'obs-list', role: 'list' });
    for (const item of obs.items) {
      obsList.append(
        el(
          'li',
          { role: 'listitem' },
          el('span', { class: `vis vis-${item.visibility}`, 'aria-hidden': 'true' }, item.visibility === 'readable' ? '👁' : '⬚'),
          el('strong', {}, `${item.label}: `),
          item.value,
          el('span', { class: 'vis-word' }, item.visibility === 'readable' ? ' — readable' : ' — opaque'),
        ),
      );
    }

    out.replaceChildren(
      el('h4', {}, `The record for ${host}`),
      fieldTable('HTTPS record', [
        ['Owner / query name', host],
        ['Type', 'HTTPS (RFC 9460)'],
        ['SvcParams', `alpn=h2 · ech=<ECHConfigList, ${serializeECHConfigList([state.server.config]).length} B>`],
      ]),
      hexDump(rdata, [], 'HTTPS record RDATA bytes (real RFC 9460 encoding)'),
      el('h4', {}, 'What the same observer saw during the lookup (modeled)'),
      obsList,
      el(
        'div',
        { class: 'verdicts' },
        transport === 'plaintext'
          ? chip('alarm', 'Verdict:', `you asked the network, in cleartext, for the ECH key of “${host}” — the name leaked before TLS began, and everything the ECH packet later hides was already spent`)
          : chip('ok', 'Verdict:', 'the lookup is opaque to this on-path observer; the destination name now appears nowhere in cleartext'),
        transport === 'doh'
          ? chip('warn', 'Trust moved, not removed:', 'the DoH resolver still sees every name you ask about')
          : chip('fact', 'Fix:', 'switch the lookup to encrypted DNS above and run it again'),
      ),
    );
  }

  // The record names the destination and carries the server's current
  // ECHConfig bytes; both change out from under it.
  onLabInputChange(() => {
    if (!out.firstChild) return;
    out.replaceChildren(staleNotice('that lookup', 'Look up the ECHConfig again.'));
  });

  lookupBtn.addEventListener('click', run);
  return panel;
}
