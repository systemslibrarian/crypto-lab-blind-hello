# Blind Hello — TLS Encrypted Client Hello (ECH)

**The ClientHello SNI field encrypted under HPKE — showing that TLS protected everything except the one field that says who you're talking to.**

## What It Is

TLS 1.3 (RFC 8446) encrypts the server's certificate and every byte after the handshake — and then announces the destination hostname in cleartext, in the SNI field of the very first packet. Encrypted Client Hello (draft-ietf-tls-esni; problem statement in RFC 8744) is HPKE (RFC 9180) applied to that one field: the client builds a second, secret ClientHello naming the real destination, seals it to the server's published key, and ships it inside a decoy ClientHello that names only the provider's public hostname.

The lesson: a protocol can be cryptographically flawless and still leak the metadata that actually matters. Both indicators are rendered separately throughout this demo — "the crypto is valid" and "your hostname leaked" are shown side by side, because both are true at once.

This lab is the first consumer of the fleet's HPKE hub: every seal and open runs the implementation from [crypto-lab-hpke-envelope](https://github.com/systemslibrarian/crypto-lab-hpke-envelope), imported as source and KAT-verified from this repo's own test suite. Nothing cryptographic is reimplemented here.

**Not production crypto — a teaching demo.** No packets leave the page; the wire and the DNS transaction are labelled models around real cryptographic operations.

## Exhibits

1. **The observer panel** (the headline): pick a destination, put two genuinely-built ClientHellos on the wire — plain and ECH — and read them through the same byte-level observer. Without ECH the hostname is literally legible in the hex dump's ASCII column; with ECH the observer gets the decoy name and an opaque HPKE payload. The observer also honestly reports what ECH does **not** hide: destination IP, ALPN, ECH's own presence, config_id, payload length.
2. **Inner and outer**: step through the construction — inner ClientHello, the emptied-and-padded `EncodedClientHelloInner`, the HPKE seal with `info = "tls ech" ‖ 0x00 ‖ ECHConfig`, and the outer-with-zeroed-payload that is the AAD. Then run the swap attack: rewrite the outer around the stolen ciphertext and watch the real AEAD open fail.
3. **The bootstrap problem** (the honest centerpiece): the ECH key arrives via the DNS HTTPS record (real RFC 9460 RDATA encoding shown). Run the lookup over plaintext DNS and the observer reads your destination before TLS ever starts; switch to encrypted DNS (modeled, labelled) to close the leak. The circularity is named in-page: ECH requires DoH/DoT to mean anything.
4. **Break it yourself**: flip one bit of the ECHConfig public key, or use a stale key after the server rotates — the server's real HPKE decryption fails, fail-closed, and the retry_configs recovery path completes a successful second attempt.
5. **GREASE**: a client with no ECHConfig sends a fake ECH extension; a field-for-field comparison (computed from the parsed bytes, not asserted) shows the observer has no bit to select on. If only ECH users sent ECH, ECH would be a selector.
6. **Deployment honesty**: draft status, real deployment, real blocking, and precisely what this demo does and does not prove.

## When to Use It

- To understand why "TLS is encrypted" and "your ISP knows every site you visit" were both true for two decades.
- To see the AAD-binding pattern — authenticate the envelope, encrypt the letter — in a deployed protocol.
- To understand why encrypted DNS and ECH only work as a pair.
- **Do NOT use it** as an ECH implementation, to assess your own network's ECH behavior, or as evidence that ECH defeats active adversaries or traffic analysis — it demonstrates a passive observer of the first packet, nothing more.

## Live Demo

<https://systemslibrarian.github.io/crypto-lab-blind-hello/> — pick a destination, send both ClientHellos, read the wire like an observer, break the config, and compare a GREASE client against the real thing.

## What Can Go Wrong

- **Plaintext DNS next to ECH** — the lookup for the ECH key announces the name ECH exists to hide. The protection is spent before TLS starts.
- **Stale ECHConfig** — DNS caches outlive key rotations; the draft's answer is trial decryption plus retry_configs, both runnable here.
- **Tampered ECHConfig** — sealing to a corrupted key is a denial of ECH, not a disclosure: the decryption fails closed and the name stays inside the ciphertext.
- **Networks that block ECH** — clients that retry without ECH trade privacy for availability; that boundary is a policy choice, not a cryptographic one.
- **A dedicated IP** — ECH hides *which* site behind a shared provider; an IP hosting one site identifies itself.

## Real-World Usage

Cloudflare enables ECH across free zones; Firefox 118+ supports it when DoH is on; Chrome 117+ rolled it out alongside its secure-DNS support. China's national firewall has blocked ESNI/ECH-bearing TLS since 2020, and Russian authorities have moved to restrict hostname-hiding TLS extensions — ECH's deployment story is inseparable from the interests of the networks it blinds.

## How to Run Locally

This lab **consumes the HPKE hub as a sibling checkout** — clone both repos side by side:

```
git clone https://github.com/systemslibrarian/crypto-lab-hpke-envelope
git clone https://github.com/systemslibrarian/crypto-lab-blind-hello
cd crypto-lab-hpke-envelope && npm ci && cd ..
cd crypto-lab-blind-hello && npm ci
npm run dev        # serve
npm test           # unit tests + KATs (46)
npm run build      # typecheck + production build
npm run test:a11y  # axe WCAG 2.1 AA gate, both themes (requires: npx playwright install chromium)
```

## Related Demos

- [crypto-lab-hpke-envelope](https://systemslibrarian.github.io/crypto-lab-hpke-envelope/) — the HPKE implementation this lab imports, with every internal stage exposed.
- [crypto-lab-tls-handshake](https://systemslibrarian.github.io/crypto-lab-tls-handshake/) / [crypto-lab-pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/) — the handshake that follows the ClientHello.
- [crypto-lab-blind-relay](https://systemslibrarian.github.io/crypto-lab-blind-relay/) — OHTTP: hiding metadata from the server rather than the network.
- [crypto-lab-downgrade-wire](https://systemslibrarian.github.io/crypto-lab-downgrade-wire/) — what "the client retries without the protection" costs, as a genre.

## Build & Verify

- **46 unit tests** (Vitest), all passing, including **known-answer tests from RFC 9180 Appendix A run through the consumed hub**: the two Base-mode vectors this lab's suite uses — A.1.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM) and A.2.1 (ChaCha20-Poly1305) — covering key derivation, encapsulation/decapsulation, the full key schedule, all 10 vector encryptions with nonce sequencing, and all 6 exporter values. ECH itself is an IETF draft and publishes no test vectors; the ECH layer is verified by round-trip against the real HPKE, strict-parser fail-closed tests, AAD-binding/tamper tests, padding-equalization tests, and GREASE indistinguishability checks — and this README says so rather than inventing vectors.
- **Accessibility gate**: `@axe-core/playwright` scans the production build in both themes for WCAG 2.1 A/AA with every interactive flow driven first; the Pages deploy is blocked on failure.
- **Deploy**: GitHub Actions checks out this repo and the hub side by side, runs typecheck → tests → build → a11y gate → Pages.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
