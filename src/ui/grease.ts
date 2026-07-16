/**
 * GREASE ECH — if only ECH users send ECH, ECH is a selector. The comparison
 * below is computed from the two parsed extensions, not asserted.
 */
import { greaseClientHello, sealEch } from '../ech/ech';
import { observeClientHello } from '../ech/observer';
import { AEAD_NAMES, type AeadId } from '../ech/hub';
import { chip, el } from './dom';
import { PUBLIC_NAME, SERVER_IP, state } from './state';

export function greasePanel(): HTMLElement {
  const panel = el('section', { class: 'panel', 'aria-labelledby': 'grease-h' });
  panel.append(
    el('h2', { id: 'grease-h' }, 'GREASE — everyone sends ECH, even those who can’t'),
    el(
      'p',
      { class: 'panel-lede' },
      'Suppose only clients with a real ECHConfig sent the extension. Then “sends ECH” itself would tag exactly the users trying to hide — a censor could select on it. ' +
        'So clients WITHOUT a config send a fake one: random config_id, a fresh random KEM share, random bytes where the ciphertext would be. ' +
        'Anti-fingerprinting as a design requirement, in the spec itself.',
    ),
  );

  const btn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Put a real-ECH client and a GREASE client on the wire');
  panel.append(el('div', { class: 'controls' }, btn));
  const out = el('div', { class: 'grease-out', role: 'status', 'aria-live': 'polite' });
  panel.append(out);

  async function run(): Promise<void> {
    btn.disabled = true;
    try {
      const sealed = await sealEch({ innerServerName: state.hostname, config: state.server.config });
      const real = observeClientHello(sealed.wire, { ip: SERVER_IP, port: 443 });
      const greaseWire = greaseClientHello(PUBLIC_NAME, real.echOuter!.payloadLen);
      const fake = observeClientHello(greaseWire, { ip: SERVER_IP, port: 443 });
      // run the GREASE hello through the real server so the copy below reports
      // observed behavior, not an assertion
      const greaseResult = await state.server.accept(greaseWire);

      const rows: [string, string, string][] = [
        ['SNI', real.sniVisible ?? '—', fake.sniVisible ?? '—'],
        ['config_id', String(real.echOuter!.configId), String(fake.echOuter!.configId)],
        ['cipher suite', `HKDF-SHA256 / ${AEAD_NAMES[real.echOuter!.aeadId as AeadId]}`, `HKDF-SHA256 / ${AEAD_NAMES[fake.echOuter!.aeadId as AeadId]}`],
        ['enc length', `${real.echOuter!.encLen} B`, `${fake.echOuter!.encLen} B`],
        ['payload length', `${real.echOuter!.payloadLen} B`, `${fake.echOuter!.payloadLen} B`],
        ['payload contents', 'HPKE ciphertext (uniform bytes)', 'random bytes (uniform bytes)'],
      ];
      const table = el('table', { class: 'fieldtable compare' });
      table.append(el('caption', { class: 'sr-only' }, 'Observer-visible ECH fields: real client vs GREASE client'));
      const thead = el('thead', {}, el('tr', {}, el('th', { scope: 'col' }, 'Observer-visible field'), el('th', { scope: 'col' }, 'Real ECH client'), el('th', { scope: 'col' }, 'GREASE client (no config)')));
      const tbody = el('tbody');
      for (const [k, a, b] of rows) {
        tbody.append(el('tr', {}, el('th', { scope: 'row' }, k), el('td', {}, a), el('td', {}, b)));
      }
      table.append(thead, tbody);

      const structurallyIdentical =
        real.echOuter!.encLen === fake.echOuter!.encLen &&
        real.echOuter!.payloadLen === fake.echOuter!.payloadLen &&
        real.echOuter!.kdfId === fake.echOuter!.kdfId &&
        real.echOuter!.aeadId === fake.echOuter!.aeadId;

      out.replaceChildren(
        table,
        el(
          'div',
          { class: 'verdicts' },
          structurallyIdentical
            ? chip('ok', 'Computed comparison:', 'field-for-field identical structure and lengths — this observer has no bit to select on')
            : chip('alarm', 'Computed comparison:', 'structures differ — GREASE would be distinguishable (this should not happen)'),
          chip(
            'fact',
            'Server’s handling of the GREASE hello (just ran):',
            `hpkeOpen=${greaseResult.hpkeOpen}, action=${greaseResult.action}, retry_configs ${greaseResult.retryConfigs ? 'offered' : 'absent'} — ` +
              'identical outward behavior to a failed real decryption, so the server does not out the GREASE sender either.',
          ),
        ),
        el('p', { class: 'note' }, 'Config_ids are single random bytes, so a GREASE id can collide with a real one; the server then trial-decrypts and fails, landing in the same path. Nothing distinguishes the two from outside.'),
      );
    } finally {
      btn.disabled = false;
    }
  }

  btn.addEventListener('click', () => void run());
  return panel;
}
