/**
 * Inner/Outer construction — step through how the two ClientHellos are built
 * and WHY the outer is the HPKE AAD, then run the swap attack against the
 * real verifier and watch the real AEAD open fail.
 */
import { annotateClientHello } from '../ech/clienthello';
import { sealEch, swapOuterSni, type SealResult } from '../ech/ech';
import { chip, el, fieldTable, hexDump, legend, truncHex, type HighlightSpan } from './dom';
import { LABS } from './links';
import { state } from './state';

function stage(n: number, title: string, ...body: (HTMLElement | string)[]): HTMLElement {
  return el('li', { class: 'stage' }, el('h4', {}, `${n}. ${title}`), ...body);
}

export function innerOuterPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', 'aria-labelledby': 'io-h' });
  panel.append(
    el('h2', { id: 'io-h' }, 'Inner and outer — why the whole outer is the AAD'),
    el(
      'p',
      { class: 'panel-lede' },
      'ECH builds two ClientHellos. The inner one names your real destination and gets encrypted; the outer one is the envelope the world sees. ' +
        'The trick that makes it safe: the outer ClientHello — every byte of it, with the ciphertext slot zeroed — is the HPKE additional authenticated data. ' +
        'Move the ciphertext into any other envelope and the decryption itself fails.',
    ),
  );

  const buildBtn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Build and seal');
  const swapBtn = el('button', { class: 'btn', type: 'button', disabled: true }, 'Attack: swap the outer (rewrite outer SNI, keep the ciphertext)');
  panel.append(el('div', { class: 'controls' }, buildBtn, swapBtn));

  const stages = el('ol', { class: 'stages', role: 'list' });
  const attackOut = el('div', { class: 'verdicts', role: 'status', 'aria-live': 'polite' });
  panel.append(stages, attackOut);

  let sealed: SealResult | undefined;

  async function build(): Promise<void> {
    buildBtn.disabled = true;
    attackOut.replaceChildren();
    try {
      sealed = await sealEch({ innerServerName: state.hostname, config: state.server.config });
      const ann = annotateClientHello(sealed.aad);
      const echExt = ann.extensions.find((e) => e.type === 0xfe0d);
      const aadHighlights: HighlightSpan[] = [];
      if (ann.sniValueSpan) aadHighlights.push({ span: ann.sniValueSpan, cls: 'hl-info', label: 'outer SNI (public name)' });
      if (echExt) {
        aadHighlights.push({
          span: { start: echExt.bodySpan.end - sealed.payload.length, end: echExt.bodySpan.end },
          cls: 'hl-ok',
          label: 'payload slot, zeroed — the hole the ciphertext will fill',
        });
      }

      stages.replaceChildren(
        stage(
          1,
          'ClientHelloInner — the truth',
          fieldTable('ClientHelloInner fields', [
            ['SNI', state.hostname],
            ['ech extension', 'type = inner (1-byte marker)'],
            ['serialized', `${sealed.innerWire.length} bytes`],
          ]),
        ),
        stage(
          2,
          'EncodedClientHelloInner — emptied and padded',
          fieldTable('Encoding', [
            ['legacy_session_id', 'emptied (the outer echoes it; the server restores it)'],
            ['struct', `${sealed.encodedInner.structLen} bytes`],
            ['zero padding', `${sealed.encodedInner.paddingLen} bytes — pads the name to maximum_name_length, then rounds to a multiple of 32, so the ciphertext length does not whisper the name length`],
          ]),
        ),
        stage(
          3,
          'HPKE seal — the consumed hub does the real work',
          fieldTable('HPKE (RFC 9180, Base mode)', [
            ['info', `"tls ech" ‖ 0x00 ‖ ECHConfig (${sealed.info.length} B) — the encryption is bound to the exact config`],
            ['enc (ephemeral KEM share)', truncHex(sealed.enc, 16)],
            ['payload', `${sealed.payload.length} bytes of AEAD ciphertext`],
          ]),
          el(
            'p',
            { class: 'note' },
            'Every intermediate of this seal — KEM, key schedule, nonce — is on display in the ',
            el('a', { href: LABS.hpkeEnvelope }, 'HPKE Envelope lab'),
            ', whose implementation this lab imports and runs unchanged.',
          ),
        ),
        stage(
          4,
          'ClientHelloOuter with the payload zeroed — this exact byte string is the AAD',
          hexDump(sealed.aad, aadHighlights, 'The AAD: outer ClientHello with a zeroed payload slot'),
          legend(aadHighlights),
        ),
        stage(
          5,
          'Splice — the sealed payload drops into the slot; everything else is byte-identical',
          el('p', {}, el('code', {}, `wire = AAD with payload := ${truncHex(sealed.payload, 12)}`)),
        ),
      );
      swapBtn.disabled = false;
    } finally {
      buildBtn.disabled = false;
    }
  }

  async function attack(): Promise<void> {
    if (!sealed) return;
    swapBtn.disabled = true;
    try {
      const swapped = swapOuterSni(sealed.wire, 'attacker.example');
      const result = await state.server.accept(swapped);
      attackOut.replaceChildren(
        el('h4', {}, 'Attacker swapped the envelope. The server ran the real decryption:'),
        chip(
          'fact',
          'HPKE open:',
          result.hpkeOpen === 'fail' ? 'FAILED — AEAD tag did not verify (the AAD the server rebuilt from the tampered outer differs)' : result.hpkeOpen,
        ),
        chip('fact', 'Server action:', 'continues as the public-name server and offers retry_configs — the designed fallback'),
        chip('ok', 'Verdict:', 'the binding held. The inner ClientHello was never processed and your destination never left the ciphertext'),
        el(
          'p',
          { class: 'note' },
          `Precisely what the attacker achieved: a failed decryption (${JSON.stringify(result.openError ?? '')}). ` +
            'Not the inner name, not a redirected inner connection.',
        ),
      );
    } finally {
      swapBtn.disabled = false;
    }
  }

  buildBtn.addEventListener('click', () => void build());
  swapBtn.addEventListener('click', () => void attack());
  return panel;
}
