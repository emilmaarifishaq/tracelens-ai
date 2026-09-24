# Sample Capture Strategy

TraceLens should use public example captures as a repeatable decoder and analysis test suite. The Wireshark SampleCaptures wiki is useful because it organizes captures by protocol, file format, and scenario, and many entries describe what behavior the trace is meant to demonstrate.

Source:

- https://wiki.wireshark.org/samplecaptures

## How TraceLens Should Use It

Do not treat public captures as product data. Treat them as regression fixtures:

- Verify TShark extraction still works after parser changes.
- Verify the normalized event model keeps stable fields.
- Verify the ladder view handles different protocols and encapsulations.
- Verify rule detection finds known failures or clearly reports "no supported failure found".
- Verify AI context stays small, masked, and evidence-based.

## Capture Selection Rules

Prefer captures that are:

- Publicly downloadable from reputable project, vendor, standards, or test-suite sources.
- Small enough for fast local and CI tests.
- Clearly described with protocol, expected behavior, and known scenario.
- Useful for one specific decoder feature or rule.
- Free of obvious private subscriber, customer, or production payload data.

Avoid committing third-party PCAPs directly unless the license and redistribution terms are explicit. For most external captures, store only metadata and a download script.

`samples/community/` is a deliberate, narrow exception: small, contributor-provided real S1AP/Diameter/GTP captures with no payload data beyond standard control-plane signaling, committed directly (see its own README.md for provenance and what each one verifies) so they're usable as regression fixtures without a download step. This is not the default -- prefer the metadata-plus-download-script approach above for anything larger or of uncertain provenance.

## Initial TraceLens Target Set

| Area | Useful Wireshark Categories | TraceLens Use |
| --- | --- | --- |
| SCTP | SCTP handshake, ASCONF, INIT collision | NGAP/S1AP/SIGTRAN transport normalization and ladder timing |
| SIGTRAN | ISUP, CAMEL, GSM MAP over SCTP/IP | Future SS7/SIGTRAN flow support |
| SIP/RTP | SIP calls, RTP codecs, rejected media changes | IMS and VoLTE call-flow ladder support |
| GSM/UMTS | Abis reject, IuB, Iu-CS call traces | Legacy RAN/core expansion and failure examples |
| DNS | DNS examples, DNS on non-standard ports | Service discovery, NRF/DNS troubleshooting, port override testing |
| RADIUS | RADIUS protocol captures | AAA expansion beyond Diameter |
| IPsec/TLS/DTLS | Encrypted/decrypted examples | Clear reporting when payload cannot be decoded |
| PCAPNG formats | Multi-interface pcapng examples | Upload compatibility and capture metadata handling |

## Regression Matrix

Each external sample we adopt should get a small manifest entry:

```yaml
id: wireshark-sctp-init-collision
source_url: https://wiki.wireshark.org/samplecaptures
file_name: SCTP-INIT-Collision.cap
protocols:
  - SCTP
scenario: SCTP association setup collision
expected:
  min_events: 1
  protocols:
    - SCTP
  errors: []
notes: Use as transport and ladder regression before adding NGAP/S1AP rules.
```

## Next Additions

1. Add `samples/external-captures.yaml` as the manifest.
2. Add a downloader script that fetches only approved public captures into an ignored local cache.
3. Add a decoder smoke-test command that runs each downloaded capture through TraceLens.
4. Add expected outputs for selected telecom failures once the decoder supports each protocol.
5. Keep generated synthetic telecom failures in this repo for cases where public samples are not available.
