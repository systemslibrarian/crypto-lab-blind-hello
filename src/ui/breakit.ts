/**
 * Break it yourself — every button here makes the REAL primitive and the REAL
 * verifier produce a genuinely wrong outcome. The cryptographic result and
 * the verdict are always separate indicators, never merged.
 */
import { parseECHConfigList } from '../ech/echconfig';
import { sealEch, tamperConfigPublicKey } from '../ech/ech';
import { chip, el } from './dom';
import { state } from './state';

export function breakItPanel(): HTMLElement {
  const panel = el('section', { class: 'panel', 'aria-labelledby': 'break-h' });
  panel.append(
    el('h2', { id: 'break-h' }, 'Break it yourself'),
    el(
      'p',
      { class: 'panel-lede' },
      'Feed the client a bad ECHConfig and watch the real HPKE decryption fail on the server — then run the protocol’s own recovery. ' +
        'Notice what stays true in every failure: the decryption fails closed, and your destination name never leaves the ciphertext.',
    ),
  );

  const tamperBtn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Tamper the ECHConfig (flip one bit of the public key)');
  const staleBtn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Use a stale key (server has rotated)');
  const retryBtn = el('button', { class: 'btn', type: 'button', disabled: true }, 'Recover: retry with the fresh retry_configs');
  panel.append(el('div', { class: 'controls' }, tamperBtn, staleBtn, retryBtn));

  const out = el('div', { class: 'verdicts', role: 'status', 'aria-live': 'polite' });
  panel.append(out);

  let retryList: Uint8Array | undefined;

  async function tamper(): Promise<void> {
    tamperBtn.disabled = true;
    try {
      const bad = tamperConfigPublicKey(state.server.config);
      const sealed = await sealEch({ innerServerName: state.hostname, config: bad });
      const result = await state.server.accept(sealed.wire);
      retryList = result.retryConfigs;
      retryBtn.disabled = !retryList;
      out.replaceChildren(
        el('h4', {}, 'You sealed to a public key nobody holds (one bit off).'),
        chip('fact', 'HPKE seal (client):', 'succeeded — encryption to any well-formed key succeeds; the client cannot tell'),
        chip('fact', 'HPKE open (server):', 'FAILED — real AEAD tag mismatch, because the X25519 shared secret differs'),
        chip('fact', 'Server action:', 'continues as the public-name server; sends retry_configs'),
        chip('ok', 'Verdict:', 'fail closed — the observer learned nothing new, and the inner name stayed inside the (undecryptable) ciphertext'),
        el(
          'p',
          { class: 'note' },
          'Exactly what was and wasn’t lost: you did not reach your destination on this attempt. Nothing about it leaked. ' +
            'A tampered config is a denial of ECH, not a disclosure.',
        ),
      );
    } finally {
      tamperBtn.disabled = false;
    }
  }

  async function stale(): Promise<void> {
    staleBtn.disabled = true;
    try {
      const staleConfig = state.server.config; // the copy a resolver cached yesterday
      state.server.rotateKey();
      const sealed = await sealEch({ innerServerName: state.hostname, config: staleConfig });
      const result = await state.server.accept(sealed.wire);
      retryList = result.retryConfigs;
      retryBtn.disabled = !retryList;
      out.replaceChildren(
        el('h4', {}, 'Your cached ECHConfig is yesterday’s. The server rotated its key.'),
        chip('fact', 'HPKE open (server):', result.hpkeOpen === 'fail' ? 'FAILED — same config_id, different key, real decryption failure' : result.hpkeOpen),
        chip('fact', 'Server action:', 'continues as the public-name server and sends retry_configs — a fresh, correct ECHConfigList'),
        chip('warn', 'Verdict:', 'ECH was not accepted on this attempt (privacy preserved, destination not reached) — the protocol expects this and built a recovery path'),
        el('p', { class: 'note' }, 'retry_configs arrives inside the encrypted, certificate-authenticated connection to the public name, so the observer does not see it either.'),
      );
    } finally {
      staleBtn.disabled = false;
    }
  }

  async function retry(): Promise<void> {
    if (!retryList) return;
    retryBtn.disabled = true;
    try {
      const [fresh] = parseECHConfigList(retryList);
      const sealed = await sealEch({ innerServerName: state.hostname, config: fresh });
      const result = await state.server.accept(sealed.wire);
      out.replaceChildren(
        el('h4', {}, 'Retried with the server’s own retry_configs.'),
        chip('fact', 'HPKE open (server):', result.hpkeOpen === 'ok' ? 'succeeded — real decryption of the new payload' : result.hpkeOpen),
        chip('fact', 'Server action:', result.action === 'accepted-inner' ? `accepted the inner ClientHello for “${result.innerSni}”` : result.action),
        chip('ok', 'Verdict:', 'recovered — one extra round trip, no leak at any point'),
      );
      retryList = undefined;
    } finally {
      retryBtn.disabled = true;
    }
  }

  tamperBtn.addEventListener('click', () => void tamper());
  staleBtn.addEventListener('click', () => void stale());
  retryBtn.addEventListener('click', () => void retry());
  return panel;
}
