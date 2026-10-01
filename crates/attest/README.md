# Notary admission

Normal clients must pair with the API before proving. The public API authenticates the device,
rate-limits its user, and requests an admission ticket from the notary's private HTTP service.

1. Client sends a signed `POST /v1/notary/admission` with `{}`.
2. API sends `POST /admission` with `{"subject":"<user-id>"}` to the private verifier endpoint.
3. Notary returns `{"ticket":"<64 hex characters>","expires_in":60}`.
4. Client opens the notary TCP connection and sends exactly `TMX1` followed by the 32 decoded ticket bytes.
5. Notary consumes the ticket once, reserves a session slot, and returns byte `0` before TLSN starts.
   Byte `1` means busy; invalid or expired admissions close the connection.

Tickets are random 256-bit capabilities. Treat them as short-lived secrets; never log them.
They are issued over the authenticated HTTPS API and are not bound to the client's source IP,
so mobile/NAT address changes do not invalidate them. This is admission control; attestations
continue to rely on the separately trusted notary signing key.

## Defaults

| Resource | Limit |
| --- | --- |
| Expensive MPC sessions | 2 |
| Concurrent cheap admission handshakes | 32 |
| Live connections per source IP | 4 |
| New handshake tasks | 64/second with burst 64 |
| Pending tickets | 1,024 total; 1 per user |
| Active authenticated sessions | 1 per user |
| Ticket expiry | 60 seconds |
| Admission preface deadline | 5 seconds |
| TLSN configuration deadline | 15 seconds |
| Whole MPC session deadline | 240 seconds |
| Attestation request/response | 8 MiB |
| Concurrent private proof verifications, including body reads | 2 |
| Private verifier JSON body | 4 MiB; 5-second deadline |
| Private admission JSON body | 256 bytes; 5-second deadline; 32 concurrent |

Expired tickets are removed before issuance; consumed tickets cannot be replayed. Peer state is
removed on disconnect. Overload is rejected immediately without queuing extra tasks. Timeout,
error, and server cancellation abort the session driver and release subject, peer, and session
permits. Private verification retains its worker permit until blocking work actually completes,
even when the HTTP caller disconnects.

The three concurrency knobs are configurable with `TMX_NOTARY_MAX_SESSIONS`,
`TMX_NOTARY_MAX_HANDSHAKES`, and `TMX_NOTARY_MAX_PER_IP`. Leave forwarding headers out of peer
identity; the TCP peer is authoritative. Keep the private HTTP port unexposed to the public
internet: it can verify proofs and mint tickets. One notary process owns these in-memory tickets.
The API must reach that same process. The deployment must also bound container memory, CPU, and
PIDs: the pinned TLSN library allows a large multiplexed receive window per admitted session.
Network-level volumetric DDoS protection remains the host/provider's responsibility.

## Local development

Prefer the same ticket flow locally. Low-level debugging can explicitly start a loopback
notary with `serve --listen 127.0.0.1:7047 --allow-unauthenticated` and run the proof CLI with
`prove --allow-unauthenticated`. Both sides enforce loopback for this development path. Normal
CLI/desktop sync never falls back to unauthenticated proving. For an authenticated manual
proof, pass `TMX_NOTARY_TICKET` through the environment, then run `tmx-attest prove`.

Run `cargo test -p tmx-attest -p tmx-core` to exercise admission expiry/replay/capacity, raw TCP
limits, setup/session cancellation, and client behavior. These tests make no paid provider calls.
