# REALITY "processed invalid connection" Error Analysis

## Summary

The error `"REALITY: processed invalid connection"` originates from the **metacubex/utls** library (specifically `reality.go`), NOT from sing-box itself. sing-box's `reality_server.go` is a thin wrapper that delegates to `utls.RealityServer()`.

---

## 1. Where the Error Is Generated

### Source: `github.com/metacubex/utls` - `reality.go`

The error is thrown at the very end of the `RealityServer()` function:

```go
// At the end of RealityServer() in metacubex/utls/reality.go:
if hs.c.isHandshakeComplete.Load() {
    return hs.c, nil
}
conn.Close()
return nil, errors.New("REALITY: processed invalid connection") // TODO: Add details.
```

This is a **catch-all error** - it fires whenever the REALITY handshake does not complete successfully, regardless of the specific failure reason. The upstream `XTLS/REALITY` library has an improved version with detailed failure reasons (see below).

### How sing-box calls it

In `common/tls/reality_server.go` (both v1.12.13 and v1.13.5):

```go
func (c *RealityServerConfig) ServerHandshake(ctx context.Context, conn net.Conn) (Conn, error) {
    tlsConn, err := utls.RealityServer(ctx, conn, c.config)
    if err != nil {
        return nil, err
    }
    return &realityConnWrapper{Conn: tlsConn}, nil
}
```

So the error propagates directly from `utls.RealityServer()` → sing-box.

---

## 2. All Possible Causes of This Error

The `RealityServer()` function runs two goroutines. The handshake fails (`isHandshakeComplete` stays false) if ANY of these conditions occur:

### Goroutine 1 (Client Hello Processing):

1. **`readClientHello()` fails** - The incoming connection doesn't contain a valid TLS Client Hello
2. **TLS version mismatch** - `hs.c.vers != VersionTLS13` - Client is not using TLS 1.3
3. **Server name mismatch** - `!config.ServerNames[hs.clientHello.serverName]` - The SNI doesn't match configured server names
4. **No suitable X25519 key share** - Client Hello doesn't contain an X25519 or X25519MLKEM768 key share with correct length (32 bytes for X25519, or `mlkem.EncapsulationKeySize768 + 32` for X25519MLKEM768)
5. **Curve25519 ECDH failure** - `curve25519.X25519(config.PrivateKey, peerPub)` returns error
6. **HKDF key derivation failure** - HKDF expansion fails
7. **AEAD decryption failure** - `aead.Open()` fails on the session ID - This means the client's encrypted payload cannot be decrypted, indicating **wrong private key, wrong public key, or data corruption**
8. **Client version out of range** - `MinClientVer`/`MaxClientVer` check fails
9. **Time difference too large** - `config.MaxTimeDiff != 0 && config.time().Sub(hs.ClientTime).Abs() > config.MaxTimeDiff` - Clock skew between client and server exceeds threshold
10. **Short ID mismatch** - `!config.ShortIds[hs.ClientShortId]` - Client's short ID not in server's allowed set

### Goroutine 2 (Target Server Handshake Mirroring):

11. **Target connection closed prematurely** - The handshake destination server closes the connection before completing
12. **Target response too large** - `len(s2cSaved) > realitySize (8192)` 
13. **Invalid TLS record format from target** - Wrong record type, wrong version, etc.
14. **Server Hello from target is malformed** - `hs.hello.unmarshal()` fails, or wrong TLS version, or unsupported cipher suite, or wrong key share group/size
15. **Handshake execution failure** - `hs.handshake()` returns error
16. **Client Finished read failure** - `hs.readClientFinished()` returns error
17. **Target sends copying data before handshake completes** - `copying` flag is set

### Key validation flow (the critical path):

```
readClientHello → check TLS 1.3 → check SNI → find X25519 key share
→ ECDH with server private key → HKDF derive auth key → AES-GCM decrypt session ID
→ extract ClientVer, ClientTime, ClientShortId
→ validate version range, time diff, short ID
→ if ALL pass: hs.c.conn = conn (marks as authenticated)
→ otherwise: connection is forwarded to handshake target (fallback)
```

---

## 3. Dependency Versions

| Component | v1.12.13 | v1.13.5 |
|-----------|----------|---------|
| `metacubex/utls` | **v1.8.3** | **v1.8.4** |
| `sagernet/sing` | v0.7.13 | v0.8.3 |
| `sagernet/sing-mux` | v0.3.3 | v0.3.4 |
| `sagernet/gvisor` | 20250325... | 20250811... |
| `sagernet/quic-go` | v0.52.0-mod.3 | v0.59.0-mod.4 |
| `sagernet/sing-tun` | v0.7.3 | v0.8.6 |
| `sagernet/gomobile` | v0.1.8 | v0.1.12 |
| `sagernet/tailscale` | v1.80.3-mod.2 | v1.92.4-mod.7 |

### utls v1.8.3 → v1.8.4 diff:

**The `reality.go` file is IDENTICAL between v1.8.3 and v1.8.4.** The only change was in `u_parrots.go` - adding a missing padding extension for the Chrome 120 fingerprint:

```diff
+               &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
```

This means the REALITY server-side logic in the `utls` library **did NOT change** between sing-box v1.12.13 and v1.13.5.

---

## 4. What Changed Between v1.12.13 and v1.13.5

### reality_server.go changes (sing-box wrapper):

1. **Return type changed**: `*RealityServerConfig` → `ServerConfig` (interface)
2. **Logger type changed**: `log.Logger` → `log.ContextLogger`
3. **New validation**: Added check for `CurvePreferences` (unavailable in reality)
4. **New validation**: Added check for `ClientCertificatePublicKeySHA256` (unavailable in reality)
5. **New validation**: Added ECH conflict check (`Reality is conflict with ECH`)
6. **New feature**: Added kTLS (kernel TLS) support wrapping
7. **Renamed**: `Config()` → `STDConfig()`

None of these changes affect the core REALITY handshake logic or the "processed invalid connection" error path.

### reality_client.go changes (sing-box wrapper):

1. **Logger parameter added** to `NewRealityClient()`
2. **kTLS support added** for client side
3. **Renamed**: `Config()` → `STDConfig()`

Again, no changes to the core REALITY handshake.

### server.go changes:

1. **Added `ServerOptions` struct** with `KTLSCompatible` field
2. **Added `NewServerWithOptions()`** function
3. **Added kTLS warnings**

---

## 5. XTLS/REALITY (Upstream) vs metacubex/utls

The upstream `XTLS/REALITY` library has a **more detailed** error message:

```go
// XTLS/REALITY tls.go (upstream, newer):
var failureReason string
if hs.clientHello == nil {
    failureReason = "failed to read client hello"
} else if hs.c.vers != VersionTLS13 {
    failureReason = fmt.Sprintf("unsupported TLS version: %x", hs.c.vers)
} else if !config.ServerNames[hs.clientHello.serverName] {
    failureReason = fmt.Sprintf("server name mismatch: %s", hs.clientHello.serverName)
} else if hs.c.conn != conn {
    failureReason = "authentication failed or validation criteria not met"
} else if hs.c.out.handshakeLen[0] == 0 {
    failureReason = "target sent incorrect server hello or handshake incomplete"
} else {
    failureReason = "handshake did not complete successfully"
}
return nil, fmt.Errorf("REALITY: processed invalid connection from %s: %s", remoteAddr, failureReason)
```

But the `metacubex/utls` fork still uses the old generic message:
```go
return nil, errors.New("REALITY: processed invalid connection") // TODO: Add details.
```

---

## 6. Most Common Causes for This Error

Based on the code analysis, the most likely causes are:

### Configuration Issues:
- **Mismatched private/public key pair** between client and server
- **Mismatched short_id** - client sends a short ID not in server's allowed list
- **Server name mismatch** - client's SNI doesn't match server config
- **Clock skew** - if `max_time_difference` is set and clocks are out of sync

### Network/Protocol Issues:
- **Non-REALITY client connecting** - any regular TLS client, port scanner, or probe will trigger this
- **Handshake target server issues** - the destination server (used for camouflage) is unreachable, returns wrong responses, or closes connection
- **Corrupted TLS data** - middlebox interference, packet corruption
- **TLS fingerprint incompatibility** - client uses a TLS fingerprint that doesn't include X25519 key shares

### Version-Specific Considerations:
- The `X25519MLKEM768` post-quantum key exchange support means clients using newer TLS fingerprints with ML-KEM/Kyber key shares are handled - but both v1.8.3 and v1.8.4 already support this
- The client code in both versions **explicitly filters out X25519MLKEM768** from the Client Hello, forcing pure X25519 for the REALITY authentication channel

---

## 7. Files Saved for Reference

All source files have been saved to `/workspace/reality-analysis/`:

- `v1.13.5/reality_server.go` - sing-box v1.13.5 REALITY server wrapper
- `v1.13.5/reality_client.go` - sing-box v1.13.5 REALITY client wrapper  
- `v1.13.5/server.go` - sing-box v1.13.5 TLS server factory
- `v1.12.13/reality_server.go` - sing-box v1.12.13 REALITY server wrapper
- `v1.12.13/reality_client.go` - sing-box v1.12.13 REALITY client wrapper
- `v1.12.13/server.go` - sing-box v1.12.13 TLS server factory
- `utls-v1.8.4/reality.go` - metacubex/utls v1.8.4 REALITY implementation (used by v1.13.5)
- `utls-v1.8.3/reality.go` - metacubex/utls v1.8.3 REALITY implementation (used by v1.12.13)
- `xtls-reality/tls.go` - upstream XTLS/REALITY implementation (with detailed error messages)
