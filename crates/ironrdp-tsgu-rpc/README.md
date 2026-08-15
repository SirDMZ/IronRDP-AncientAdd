# ironrdp-tsgu-rpc

A Microsoft RD Gateway (MS-TSGU) client over the **RPC-over-HTTP** (MS-RPCH) transport.

[`ironrdp-mstsgu`](https://docs.rs/ironrdp-mstsgu) implements the WebSocket gateway
transport; this crate covers the complementary RPC-over-HTTP transport — the universal
MS-TSGU transport that every gateway version speaks. It is a transport adapter: it
yields an `AsyncRead + AsyncWrite` tunnel to an internal RDP host, over which a caller
runs the RDP handshake (for example with `ironrdp-connector`).

## TLS backend

A TLS backend must be selected via a feature (delegated to `ironrdp-tls`):

- `rustls` (recommended)
- `native-tls`

## Usage

`open_tunnel` opens the full tunnel end-to-end and returns a `GatewayTunnel`;
`GatewayTunnel::into_async` yields the `AsyncRead + AsyncWrite` transport.

The transport is built in independently traceable layers, each with a `probe_*` entry
point (`probe_auth`, `probe_rts`, `probe_bind`, `probe_tunnel`, `probe_channel`,
`probe_pipe`) for diagnosing a real gateway one layer at a time.

## Provenance

This crate is an independent implementation of Microsoft's open specifications
(MS-RPCH, MS-TSGU, and MS-RPCE / DCE-RPC C706). FreeRDP was studied only for interop
facts (opcodes, UUIDs, wire byte-layouts, interop-mandated constants), not its
copyrightable expression. See the crate-level documentation for the full note.
