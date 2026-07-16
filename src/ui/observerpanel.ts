/**
 * THE headline mechanism: one observer, one wire, two ClientHellos — and the
 * single field that differs. Both packets are genuinely built (real
 * serialization, real HPKE seal for the ECH one); the observer genuinely
 * parses the bytes it is shown and nothing else.
 */
import { plainClientHello, sealEch } from '../ech/ech';
import { observeClientHello, type ObserverReport } from '../ech/observer';
import { asciiStrings, chip, el, hexDump, legend, type HighlightSpan } from './dom';
import { PRESET_HOSTS, SERVER_IP, setHostname, state } from './state';

function observedList(report: ObserverReport): HTMLElement {
  const ul = el('ul', { class: 'obs-list', role: 'list' });
  for (const item of report.items) {
    const li = el('li', { role: 'listitem' });
    li.append(
      el('span', { class: `vis vis-${item.visibility}`, 'aria-hidden': 'true' }, item.visibility === 'readable' ? '👁' : '⬚'),
      el('strong', {}, `${item.label}: `),
      el('span', {}, item.value),
      el('span', { class: 'vis-word' }, item.visibility === 'readable' ? ' — readable' : ' — opaque'),
    );
    ul.append(li);
  }
  return ul;
}

function stringsRow(wire: Uint8Array): HTMLElement {
  const found = asciiStrings(wire, 4);
  return el(
    'p',
    { class: 'strings-row' },
    el('strong', {}, 'Printable strings in this packet: '),
    el('code', {}, found.length ? found.join('  ') : '(none ≥ 4 chars)'),
  );
}

function wireCard(
  title: string,
  subtitle: string,
  wire: Uint8Array,
  report: ObserverReport,
  verdict: HTMLElement[],
): HTMLElement {
  const highlights: HighlightSpan[] = [];
  if (report.sniValueSpan) {
    highlights.push({
      span: report.sniValueSpan,
      cls: report.echPresent ? 'hl-info' : 'hl-alarm',
      label: report.echPresent ? 'SNI (decoy public name, readable)' : 'SNI (your destination, readable)',
    });
  }
  if (report.echPayloadSpan) {
    highlights.push({ span: report.echPayloadSpan, cls: 'hl-ok', label: 'ECH payload (HPKE ciphertext, opaque)' });
  }
  const card = el('article', { class: 'wirecard' });
  card.append(
    el('h4', {}, title),
    el('p', { class: 'note' }, subtitle),
    hexDump(wire, highlights, `${title}: ClientHello bytes as the observer sees them`),
    legend(highlights),
    stringsRow(wire),
    el('h5', {}, 'What this observer learned'),
    observedList(report),
    el('div', { class: 'verdicts' }, ...verdict),
  );
  return card;
}

export function observerPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', 'aria-labelledby': 'obs-h' });
  panel.append(
    el('h2', { id: 'obs-h' }, 'The observer panel — one field'),
    el(
      'p',
      { class: 'panel-lede' },
      'Pick a destination and put both first packets on the wire: a plain TLS 1.3 ClientHello and one carrying ECH. ' +
        'The observer below parses only the bytes shown — same wire, same parser, one field different.',
    ),
    el(
      'p',
      { class: 'note' },
      'The packets are real (real serialization, real HPKE seal); the network around them is a modeled wire view — no traffic leaves this page.',
    ),
  );

  const select = el('select', { id: 'obs-host' });
  for (const h of PRESET_HOSTS) select.append(el('option', { value: h }, h));
  select.append(el('option', { value: '__custom' }, 'custom hostname…'));
  const custom = el('input', {
    type: 'text',
    id: 'obs-custom',
    'aria-label': 'Custom destination hostname',
    placeholder: 'my-private-site.example',
    hidden: true,
  });
  select.addEventListener('change', () => {
    const isCustom = select.value === '__custom';
    custom.hidden = !isCustom;
    if (!isCustom) setHostname(select.value);
  });
  custom.addEventListener('input', () => {
    if (custom.value.trim()) setHostname(custom.value.trim());
  });

  const runBtn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Send both ClientHellos');
  const controls = el(
    'div',
    { class: 'controls' },
    el('span', { class: 'ctl' }, el('label', { for: 'obs-host' }, 'Destination you intend to reach'), select),
    el('span', { class: 'ctl' }, custom),
    runBtn,
  );
  panel.append(controls);

  const results = el('div', { class: 'wire-grid', role: 'status', 'aria-live': 'polite' });
  panel.append(results);

  async function run(): Promise<void> {
    runBtn.disabled = true;
    results.replaceChildren(el('p', { class: 'note' }, 'Building ClientHellos…'));
    try {
      const host = state.hostname;
      const plainWire = plainClientHello(host);
      const sealed = await sealEch({ innerServerName: host, config: state.server.config });
      const plainReport = observeClientHello(plainWire, { ip: SERVER_IP, port: 443 });
      const echReport = observeClientHello(sealed.wire, { ip: SERVER_IP, port: 443 });

      // Verdicts are computed from the observer's own output, not asserted:
      // EXPOSED iff the name the observer read equals the true destination.
      const plainExposed = plainReport.sniVisible === host;
      const echExposed = echReport.sniVisible === host;

      const plainCard = wireCard(
        'WITHOUT ECH',
        'TLS 1.3 will encrypt the certificate and everything after the handshake — but this first packet names your destination in cleartext.',
        plainWire,
        plainReport,
        [
          chip('fact', 'TLS 1.3 crypto:', 'flawless — every record after the handshake is encrypted (protocol property; the handshake itself lives in the tls-handshake lab)'),
          plainExposed
            ? chip('alarm', 'Privacy verdict:', `observer read your destination “${plainReport.sniVisible}” — EXPOSED`)
            : chip('ok', 'Privacy verdict:', 'destination not present in this packet'),
        ],
      );
      const echCard = wireCard(
        'WITH ECH',
        'Same ClientHello shape. The SNI now carries the provider’s decoy public name; your real destination rides inside the HPKE ciphertext.',
        sealed.wire,
        echReport,
        [
          chip('fact', 'HPKE seal:', `real RFC 9180 Base-mode encryption to the server’s key (payload ${sealed.payload.length} B)`),
          echExposed
            ? chip('alarm', 'Privacy verdict:', 'observer read your destination — EXPOSED')
            : chip('ok', 'Privacy verdict:', `observer read only “${echReport.sniVisible}” — your destination stayed inside the ciphertext`),
          chip('warn', 'One condition:', 'this holds only if the ECHConfig lookup was also encrypted — see “The bootstrap problem” below'),
        ],
      );
      results.replaceChildren(plainCard, echCard);
    } catch (e) {
      results.replaceChildren(el('p', { class: 'note' }, `Failed: ${(e as Error).message}`));
    } finally {
      runBtn.disabled = false;
    }
  }

  runBtn.addEventListener('click', () => void run());
  return panel;
}
