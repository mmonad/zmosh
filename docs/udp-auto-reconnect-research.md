# Adding UDP Auto-Reconnect to zmx

Deep research into integrating Mosh / Eternal Terminal / tssh-style UDP auto-reconnect
with zmx's session persistence.

---

## zmx Today — Architecture Recap

zmx is a remarkably compact terminal session persistence tool (~2,200 lines of Zig). Here's what matters for this analysis:

| Layer | Implementation |
|---|---|
| **Transport** | Unix domain sockets (`AF_UNIX, SOCK_STREAM`) — local only |
| **IPC Protocol** | 5-byte header (`tag:u8 + len:u32`) + payload, 11 message types |
| **Session Model** | One daemon process per session, forked from CLI |
| **Terminal State** | In-memory `ghostty_vt.Terminal` — full VT emulator with scrollback |
| **Event Loop** | Single-threaded `poll()` — no threads anywhere |
| **Re-attach** | Daemon serializes terminal state via `TerminalFormatter` → sends as `Output` IPC message |
| **Client Model** | Multiple clients can attach simultaneously; PTY output broadcast to all |

The critical insight: zmx already solves the hardest part of session persistence — it maintains a **server-side VT emulator** that tracks the complete terminal state. This is exactly what Mosh does too, but zmx does it for local sessions.

### Key Source Files

| File | Lines | Role |
|---|---|---|
| `src/main.zig` | ~1,832 | Entry point, daemon loop, client loop, PTY, attach/detach, all commands |
| `src/ipc.zig` | ~153 | Wire protocol, message framing, socket buffer |
| `src/log.zig` | ~89 | Log file management with rotation |
| `src/completions.zig` | ~139 | Shell completion scripts |

### Existing IPC Message Types

| Tag | Value | Direction | Description |
|---|---|---|---|
| `Input` | 0 | Client→Daemon | Keyboard input to write to PTY |
| `Output` | 1 | Daemon→Client | Raw PTY bytes to write to stdout |
| `Resize` | 2 | Client→Daemon | Terminal dimensions changed |
| `Detach` | 3 | Client→Daemon | Detach this client |
| `DetachAll` | 4 | Client→Daemon | Detach all clients from session |
| `Kill` | 5 | Client→Daemon | Kill session |
| `Info` | 6 | Bidirectional | Session metadata query/response |
| `Init` | 7 | Client→Daemon | First message on connect, includes terminal size |
| `History` | 8 | Bidirectional | Request/response for scrollback dump |
| `Run` | 9 | Client→Daemon | Send command to PTY without attaching |
| `Ack` | 10 | Daemon→Client | Acknowledge a `Run` command |

### Session Lifecycle

```
zmx attach <name>
  → ensureSession()
      → sessionExists() checks socket file
      → if new: createSocket() + fork()
          → child becomes daemon (setsid(), log file, spawnPty(), daemonLoop())
          → parent waits 10ms then continues
      → if existing: probeSession() (connect + send Info + receive Info response)
  → sessionConnect() → connect to Unix socket
  → attach terminal raw mode
  → clientLoop()
```

### Re-attach State Restoration

The critical path in `handleInit()`:

1. Daemon receives `Init` with new terminal dimensions
2. Calls `ioctl(TIOCSWINSZ)` and `term.resize()` (triggers reflow)
3. If this is a re-attach (not first connect): calls `serializeTerminalState()` which uses `ghostty_vt.formatter.TerminalFormatter` with `.vt` mode to emit a full VT escape sequence snapshot
4. Sends the snapshot as an `Output` message before any fresh PTY output

---

## The Three Approaches Compared

These three tools represent fundamentally different philosophies about what a "connection" is:

- **Mosh**: A connection is an illusion. There are only authenticated datagrams carrying screen state diffs. The "connection" is just "both sides have each other's key."
- **Eternal Terminal**: A connection is a TCP stream, but it should be **resumable**. Buffer what was sent, replay on reconnect.
- **tssh**: A connection should use modern UDP protocols (QUIC/KCP) that handle the hard stuff, while keeping SSH's byte-stream model.

---

## 1. Mosh — State Synchronization Protocol (SSP)

### 1.1 Architecture Overview

Mosh's architecture is fundamentally different from SSH. Rather than treating a remote shell as a byte-stream pipe, Mosh treats it as a **screen-state synchronization problem**, more akin to a video conferencing model. The protocol is called the **State Synchronization Protocol (SSP)**, and Mosh is its first (and so far only) application.

SSP is organized into three modules:

1. **Crypto module** — provides confidentiality and authenticity via AES-128-OCB3
2. **Datagram layer** — sends/receives UDP packets, manages roaming, estimates link timing
3. **Transport layer** — responsible for conveying current object state to the remote host

Mosh runs **two instances of SSP**, one in each direction:

- **Client-to-server**: Synchronizes a `UserStream` object (keystroke transcript with TCP-like ordering semantics)
- **Server-to-client**: Synchronizes a `Terminal::Complete` object (the full terminal screen state, where intermediate frames may be skipped)

### 1.2 The Datagram Format (Wire Format)

Each Mosh UDP datagram has this structure:

```
┌──────────────┬──────────────────────────┬────────────┐
│ Nonce (8B)   │ Encrypted Payload        │ OCB Tag(16)│
└──────────────┴──────────────────────────┴────────────┘
```

Inside the encrypted payload (after decryption):

```
┌───────────────┬────────────────────┬──────────────────┐
│ timestamp (2B)│ timestamp_reply(2B)│ payload (var)     │
└───────────────┴────────────────────┴──────────────────┘
```

All integers are in network byte order (big-endian).

Nonce construction (64-bit value, padded to 12 bytes for OCB):

```
Bit 63 (MSB):  Direction flag (1 = TO_CLIENT, 0 = TO_SERVER)
Bits 62..0:    Sequence number (monotonically incrementing)
```

### 1.3 Cryptographic Layer (AES-128-OCB3)

**Key generation and exchange:**

1. The `mosh` wrapper script SSHes into the server and executes `mosh-server`
2. `mosh-server` generates a 128-bit random key using a cryptographically secure PRNG
3. The key is Base64-encoded (22 characters) and printed to stdout along with the bound UDP port
4. The SSH connection is torn down
5. `mosh-client` receives the key and port, then connects directly over UDP

**Why not DTLS?** Mosh's designers chose custom crypto over DTLS because:

- DTLS does not support roaming (especially transparent roaming where the client is unaware)
- DTLS requires public-key cryptography and a replay cache
- Mosh's idempotent design eliminates the need for replay caches entirely

**Why AES-128 (not AES-256)?** The OCB FAQ recommends AES-128 as it avoids the related-key attacks that affect AES-192 and AES-256.

### 1.4 Connection Persistence and Roaming

**The mechanism is elegant in its simplicity:**

Every time the server receives an authentic datagram from the client with a sequence number **greater than any previously received**, it updates its destination to the packet's source IP address and UDP port. That is the entire roaming mechanism — one rule.

- **Heartbeat:** The client sends a datagram at least once every **3 seconds**, even if there is no user input. This serves as both a keepalive and a roaming update.
- **Single-packet roaming:** After the client changes IP addresses (e.g., WiFi to cellular), a single authenticated packet reaching the server is sufficient to complete the roam.
- **Why this works:** UDP is connectionless — there is no TCP state machine to break. Each datagram is independently authenticated. The sequence number prevents replay attacks. NAT changes are handled transparently.

**Comparison to SSH:** SSH runs over TCP, so any IP change, NAT rebinding, or prolonged sleep breaks the TCP connection. An attacker can also kill an SSH session with a single spoofed TCP RST packet. Mosh authenticates every datagram, so an attacker must continuously block packets to prevent communication.

### 1.5 Session Resumption and Timeouts

Mosh does **not** have a traditional "reconnection" mechanism because the connection is never truly established or broken at the network layer.

- `mosh-server` waits **60 seconds** for the initial client contact; exits if none arrives
- `MOSH_SERVER_NETWORK_TMOUT` controls how long the server waits (default: indefinite)
- **Limitation:** Mosh does not support reattaching after client reboot (the key is in client memory)

### 1.6 Transport Layer: State Diffs and Frame Rate

**Diff computation:**

1. `TransportSender` maintains a list of `sent_states` (timestamped snapshots)
2. It tracks `assumed_receiver_state` — the state it believes the receiver currently has
3. To send an update: `current_state.diff_from(assumed_receiver_state)` produces the diff

**Acknowledgment:**

- Each `Instruction` carries `ack_num` (highest state received from remote)
- `process_acknowledgment_through(ack_num)` prunes all states older than the ack

**Frame rate algorithm:**

| Constant | Value | Purpose |
|---|---|---|
| `SEND_INTERVAL_MIN` | 20 ms | Minimum time between frames |
| `SEND_INTERVAL_MAX` | 250 ms | Maximum time between frames |
| `ACK_INTERVAL` | 3000 ms | Time between empty acknowledgments |
| `ACK_DELAY` | 100 ms | Delay before sending ack |
| `ACTIVE_RETRY_TIMEOUT` | 10000 ms | Time before retransmission attempt |

**RTT estimation (same as TCP RFC 6298 but with 50ms min RTO):**

```
If first measurement:
  SRTT = R
  RTTVAR = R / 2
Otherwise:
  RTTVAR = (1 - 1/4) * RTTVAR + 1/4 * |SRTT - R|
  SRTT   = (1 - 1/8) * SRTT + 1/8 * R
```

### 1.7 Packet Loss and Reordering

- No explicit NACKs or retransmission requests
- If acknowledgment doesn't arrive within `timeout + ACK_DELAY`, `TransportSender` falls back to an earlier assumed state, naturally triggering a new diff
- Because diffs are idempotent, duplicates or reordered packets cause no harm
- The receiver applies state N if and only if `N > current_state_num`

**Key insight:** Because SSP synchronizes screen state (not a byte stream), it can skip intermediate states. If the server generates states 1-5 and only packet 5 arrives, the client jumps directly to state 5.

### 1.8 Predictive Local Echo

- `PredictionEngine` groups predictions into **epochs**
- An epoch begins tentatively; when the server confirms any prediction in an epoch, all predictions are displayed
- Control characters and arrow keys increment the epoch, resetting confidence
- `GLITCH_THRESHOLD` = 250ms — if a prediction is outstanding this long, mark as glitch
- On `--predict=adaptive` (default): predictions are shown only on high-latency connections, underlined to indicate uncertainty
- **Results:** 70% of keystrokes predicted correctly, median response time 4.8ms on cellular (vs 503ms for SSH)

### 1.9 State Synchronization vs. Byte-Stream

| Aspect | SSH (byte-stream) | Mosh (state sync) |
|---|---|---|
| What is transmitted | Every byte from the application | Only the current screen state (diffs) |
| Terminal emulator location | Client-side only | Server-side + client-side |
| Can skip intermediate output | No (TCP guarantees in-order) | Yes (jump to latest frame) |
| Ctrl-C responsiveness | Delayed by buffered data | Always within 1 RTT |
| Scrollback | Full (client sees all bytes) | Limited (skipped frames lost) |
| Minimum RTO | 1 second (TCP) | 50 ms |
| Port forwarding | Full support | Not supported |

---

## 2. Eternal Terminal (ET)

### 2.1 Architecture

ET keeps TCP but adds a **reliable reconnection layer** on top of it.

Three processes collaborate:

- **`et`** — client-side process
- **`etserver`** — broker/daemon listening on port 2022 (TCP)
- **`etterminal`** — per-session user-space terminal host

### 2.2 Connection Flow

```
[SSH] --> et SSHes into server, launches etterminal
etterminal --> etserver: TERMINAL_USER_INFO (client-id + passkey via FIFO)
et --> etserver: ConnectRequest (client-id, protocol version) [unencrypted]
etserver --> et: ConnectResponse (NEW_CLIENT)
et --> etserver: InitialPayload (port forwarding config, jumphost flag)
etserver --> et: InitialResponse
etserver --> etterminal: TERMINAL_INIT (TermInit)
etterminal: enters runUserTerminal loop
```

The passkey is a 32-character string generated server-side, passed to the client over SSH (which is then closed), and used as the symmetric encryption key.

### 2.3 Reconnection Mechanism (EternalTCP)

This is ET's core innovation — the `BackedReader`/`BackedWriter` abstraction.

**`BackedWriter`:**
- Wraps outgoing writes
- Encrypts each packet using `CryptoHandler`
- Stores encrypted packets in a `backupBuffer` with sequence numbers
- When TCP breaks, the buffer retains un-acknowledged packets

**`BackedReader`:**
- Wraps incoming reads
- Tracks the number of bytes/packets read (the sequence number)
- On reconnect, reports its sequence number to the remote side

**Reconnection flow:**

```
et → etserver: ConnectRequest (same client-id, version)
etserver → et: ConnectResponse (RETURNING_CLIENT)
et → etserver: SequenceHeader (last received seq number)
etserver → et: SequenceHeader (last received seq number)
et → etserver: CatchupBuffer (missing encrypted packets since server's seq)
etserver → et: CatchupBuffer (missing encrypted packets since client's seq)
```

The `CatchupBuffer` contains already-encrypted packets — they are replayed as-is.

### 2.4 Port Forwarding and Tunneling

ET supports port forwarding over the same EternalTCP connection:

| Type | Flag | Description |
|---|---|---|
| Forward tunnel | `-t source:dest` | Client port forwarded to server |
| Reverse tunnel | `-r source:dest` | Server port forwarded to client |
| Port ranges | `-t 8000-8003:9000-9003` | Multiple ports at once |
| Unix sockets | `-t ENV_VAR:/path/to/sock` | Unix socket forwarding with env var |

### 2.5 ET vs. Mosh

| Feature | Mosh | ET |
|---|---|---|
| Transport | UDP (custom SSP) | TCP (with EternalTCP layer) |
| Reconnection | Stateless (single-packet roaming) | Stateful (sequence exchange + catchup) |
| Scrollback | Lost when frames are skipped | Preserved (byte-stream model) |
| Port forwarding | Not supported | Supported (forward + reverse) |
| Predictive echo | Yes (70% of keystrokes) | No |
| IP roaming | Transparent, instantaneous | Requires TCP reconnection |
| Firewall friendliness | Requires UDP ports 60000-61000 | TCP port 2022 |

---

## 3. tssh/tsshd — Modern UDP (QUIC/KCP)

### 3.1 Architecture

tssh/tsshd uses **established UDP transport protocols** (QUIC or KCP) rather than a custom protocol. It does not implement predictive local echo or state synchronization — it transmits a byte stream like SSH.

- **`tssh --udp`** — client-side, replaces `mosh`
- **`tsshd`** — server-side, replaces `mosh-server`

### 3.2 UDP Transport: QUIC and KCP

**QUIC (default):**
- Uses TLS 1.3 with mutual authentication
- Ephemeral certificates generated during bootstrap, exchanged via SSH tunnel
- Built-in stream multiplexing

**KCP:**
- Reliable UDP protocol optimized for low-latency interactive sessions
- Uses `smux.Session` for stream multiplexing
- Uses AES-GCM-256 encryption

### 3.3 Connection Migration and Roaming

Roaming is handled by a **proxy layer** (`clientProxy`/`serverProxy`):

1. Client detects timeout (no heartbeat for `UdpHeartbeatTimeout` = 3 seconds)
2. `tryToReconnect()` is called
3. `clientProxy.renewTransportPath()` increments `serialNumber` and establishes new UDP path
4. Client sends auth packet: `[clientID(8B) | serialNumber(8B)]` encrypted with AES-GCM-256
5. Server verifies `clientID`, checks `serialNumber > all_previous` (anti-replay)
6. Server responds with `[serverID(8B) | serialNumber(8B)]` encrypted
7. Both sides flush cached packets (up to 200) to the new path

### 3.4 Heartbeat and Timeout System

| Parameter | Default | Description |
|---|---|---|
| `UdpHeartbeatTimeout` | 3 seconds | Triggers reconnection attempt |
| `UdpReconnectTimeout` | 15 seconds | Shows "connection lost" notification |
| `UdpAliveTimeout` | 86400 seconds (24h) | Both sides exit |
| Heartbeat interval | 100 ms | "alive" messages via `busStream` |

### 3.5 tssh vs. Mosh

| Feature | Mosh | tssh/tsshd |
|---|---|---|
| Data model | Screen state sync | Byte stream (like SSH) |
| UDP protocol | Custom SSP | QUIC or KCP |
| Predictive echo | Yes | No |
| Scrollback | Limited | Full |
| X11 forwarding | No | Yes |
| Agent forwarding | No | Yes |
| Port forwarding | No | Yes |
| Windows support | No | Yes |
| TCP fallback | No | Yes |

---

## 4. Comparative Summary

### Fundamental Design Philosophies

**Mosh** reimagines the problem: a remote terminal is not a byte pipe but a screen to be synchronized. By using UDP and state diffs, it achieves instant roaming, predictive echo, and extreme resilience to packet loss. The tradeoff is loss of scrollback, port forwarding, and SSH compatibility features.

**Eternal Terminal** preserves the byte-stream model but makes TCP reconnectable. By buffering encrypted packets and replaying on reconnect, it achieves session persistence while keeping scrollback, port forwarding, and tmux -CC support. The tradeoff is that roaming requires an actual TCP reconnection.

**tssh/tsshd** combines the best of both: UDP transport for resilience and roaming, while maintaining full SSH feature compatibility. It trades Mosh's predictive echo for complete SSH compatibility.

### Connection Resilience Mechanisms

| Mechanism | Mosh | ET | tssh |
|---|---|---|---|
| IP change handling | Automatic (next authenticated packet) | TCP reconnect + seq exchange | Proxy re-auth + packet cache flush |
| Sleep/wake | Seamless (UDP stateless) | Reconnects with catchup buffer | Reconnects within HeartbeatTimeout |
| Packet loss | Skip frames, send latest state | TCP handles retransmission | QUIC/KCP handle retransmission |
| Encryption key lifetime | Session lifetime (via env var) | Session lifetime (via FIFO) | Session lifetime (via SSH tunnel) |
| Heartbeat interval | 3 seconds | TCP keepalive | 100 ms |

---

## 5. How This Maps to zmx

zmx has a **massive structural advantage** over all three of these tools: it already runs a server-side `ghostty_vt.Terminal`. This means:

1. It can do Mosh-style state diffs natively (the `TerminalFormatter` already serializes screen state)
2. It doesn't need to choose between "state sync" and "byte stream" — it has BOTH (PTY bytes for real-time, terminal state for reconnect)
3. The daemon-per-session model means network transport can be added per-session without a central broker

---

## 6. Architecture Options

### Option A: "ET-style" — Buffered Byte-Stream over TCP/QUIC

**Philosophy:** Keep zmx's current byte-stream IPC model, but make it network-capable and reconnectable.

**Changes required:**

1. Replace `AF_UNIX` with `AF_INET6` (or dual-stack) in `createSocket()` / `sessionConnect()`
2. Add a packet buffer to `Client` struct (like ET's `BackedWriter`):
   ```zig
   const Client = struct {
       // existing fields...
       send_seq: u64,
       recv_seq: u64,
       backup_buf: RingBuffer(EncryptedPacket),
   };
   ```
3. Add authentication — generate session key during initial SSH bootstrap, use for AES-GCM
4. Add reconnect handshake — new IPC messages: `Reconnect` (client sends last recv_seq), `Catchup` (server replays from seq)
5. Use zmx's existing terminal state serialization as fallback — if the backup buffer has been exhausted, fall back to full `serializeTerminalState()` like zmx already does on re-attach

**Pros:** Simplest to implement, preserves full scrollback, minimal changes to existing code.
**Cons:** TCP reconnect takes time (no single-packet roaming), or requires QUIC dependency.

### Option B: "Mosh-style" — UDP State Synchronization

**Philosophy:** Replace the byte-stream IPC with a UDP datagram protocol that synchronizes terminal screen state.

**Changes required:**

1. Add UDP socket support alongside existing Unix sockets
2. Add a state-diff engine leveraging `ghostty_vt.Terminal`:
   ```zig
   const StateSyncEngine = struct {
       current_state_num: u64,
       assumed_receiver_state: ?TerminalSnapshot,
       sent_states: BoundedRingBuffer(TimestampedState),

       fn computeDiff(self: *@This()) []u8 {
           // diff current terminal state against assumed_receiver_state
           // using TerminalFormatter
       }
   };
   ```
3. Implement SSP-like transport:
   - Monotonically increasing nonces (direction bit + sequence)
   - AES-GCM or XChaCha20-Poly1305 encryption per datagram
   - RTT estimation (SRTT/RTTVAR per RFC 6298 but with 50ms min RTO)
   - Adaptive frame rate (20ms-250ms based on RTT)
4. Roaming: Update client address on every authenticated datagram with seq > max_seen_seq

**Pros:** Instant roaming (single packet), extremely resilient to packet loss, predictive echo possible.
**Cons:** Significant implementation effort, lose scrollback for skipped frames (though zmx's server-side terminal preserves it for re-attach).

### Option C: "Hybrid" — The Best of All Worlds (Recommended)

**Philosophy:** Use zmx's architectural advantages to combine the best features.

```
┌─────────────────────────────────────────────────────┐
│                    zmx daemon                        │
│  ┌─────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │   PTY   │→ │ ghostty_vt   │→ │ Transport Layer│  │
│  │ (shell) │  │  Terminal     │  │                │  │
│  └─────────┘  │ (full state   │  │ ┌────────────┐│  │
│               │  + scrollback)│  │ │Unix Socket ││  │
│               └──────────────┘  │ │(local)     ││  │
│                                  │ ├────────────┤│  │
│                                  │ │UDP Datagram││  │
│                                  │ │(remote)    ││  │
│                                  │ └────────────┘│  │
│                                  └────────────────┘  │
└─────────────────────────────────────────────────────┘
```

#### Transport Abstraction

```zig
const Transport = union(enum) {
    unix: UnixTransport,      // existing behavior, unchanged
    udp: UdpTransport,        // new: datagram-based, encrypted

    const VTable = struct {
        send: *const fn (self: *anyopaque, data: []const u8) Error!void,
        recv: *const fn (self: *anyopaque, buf: []u8) Error!usize,
        poll_fd: *const fn (self: *anyopaque) i32,
    };
};
```

#### UDP Transport (inspired by Mosh + tssh)

- Each datagram: `nonce(8) || encrypted(timestamp(2) + timestamp_reply(2) + payload) || tag(16)`
- Roaming: accept source address from any authenticated packet with seq > max_seen
- Heartbeat: client sends every 1s
- Key exchange: during initial SSH connection, generate 256-bit key, pass via stdout (like Mosh)

#### Adaptive Sync Strategy

- **Real-time mode** (normal operation): Stream raw PTY bytes as `Output` datagrams. If packets are lost, no problem — the client can request a full state snapshot.
- **Recovery mode** (after reconnect or significant loss): Daemon sends full terminal state via `serializeTerminalState()` — the mechanism zmx already uses for re-attach.
- **Scrollback on demand**: Client sends `History` request (already implemented!), daemon responds with scrollback data.

This eliminates Mosh's biggest weakness (no scrollback) because zmx keeps the full `ghostty_vt.Terminal` with scrollback on the server.

#### Bootstrap Protocol

```
1. User runs: zmx attach --remote user@host sessionname
2. zmx SSHes to host, runs: zmx serve sessionname
3. zmx serve:
   a. Creates/attaches to session daemon (same as today)
   b. Generates 256-bit session key
   c. Binds UDP port (try 60000-61000 range)
   d. Prints: ZMX_KEY=<base64key> ZMX_PORT=<port>
   e. Enters "UDP gateway" mode — bridges Unix socket <-> UDP
4. Local zmx client captures key + port from SSH stdout
5. SSH connection closes
6. Local zmx connects directly via UDP
```

#### Gateway Architecture

The `zmx serve` process acts as a bridge — the daemon itself stays unchanged:

```
┌────────────┐     UDP      ┌──────────────┐  Unix Socket  ┌──────────┐
│ zmx client │<────────────>│  zmx serve   │<─────────────>│ zmx      │
│ (local)    │  (encrypted) │  (gateway)   │  (existing    │ daemon   │
└────────────┘              └──────────────┘   IPC)        └──────────┘
```

This means you **don't have to modify the daemon at all**. The daemon continues speaking its existing Unix socket IPC protocol. Benefits:

1. Zero risk of breaking existing local sessions
2. Ability to iterate rapidly on the network protocol
3. Natural separation of concerns (network/crypto vs session/PTY)
4. Option to later integrate the gateway into the daemon once the protocol stabilizes

#### Encryption Choice for Zig

XChaCha20-Poly1305 via `std.crypto.aead.xchacha20poly1305`:

- Already in Zig's standard library — no external dependency
- 192-bit nonces — safe for random generation (no nonce reuse risk)
- Excellent performance
- AEAD (authenticated encryption with associated data)

#### UDP Datagram Format

```zig
const Datagram = packed struct {
    nonce: u64,          // MSB = direction, rest = sequence
    // --- encrypted below ---
    timestamp: u16,
    timestamp_reply: u16,
    state_num: u64,
    assumed_state: u64,  // diff computed from this state
    payload_len: u32,
    // payload follows (state diff or input bytes)
    // XChaCha20-Poly1305 tag appended (16 bytes)
};
```

#### New IPC Messages (for gateway)

| Tag | Direction | Payload |
|---|---|---|
| `Auth` | Client→Gateway | encrypted(session_key, client_id) |
| `AuthOk` | Gateway→Client | encrypted(session_key, server_id) |
| `Reconnect` | Client→Gateway | last_recv_seq: u64 |
| `StateRequest` | Client→Gateway | request full terminal state snapshot |

#### Estimated New Code

| Component | Est. Lines | Complexity |
|---|---|---|
| `src/crypto.zig` — encrypt/decrypt datagrams | ~150 | Low (Zig stdlib) |
| `src/udp.zig` — UDP transport + roaming + RTT | ~400 | Medium |
| `src/serve.zig` — gateway (Unix↔UDP bridge) | ~300 | Medium |
| `src/remote.zig` — SSH bootstrap + client connect | ~250 | Medium |
| Modifications to `main.zig` — new commands | ~200 | Low |
| **Total** | **~1,300** | |

This roughly doubles the codebase — significant but manageable.

---

## 7. Recommended Implementation Sequence

### Phase 1 — Crypto + UDP Primitives

- `crypto.zig`: XChaCha20-Poly1305 datagram encrypt/decrypt
- `udp.zig`: Non-blocking UDP socket, send/recv datagrams with nonce management
- Unit tests for both

### Phase 2 — Gateway (`zmx serve`)

- Bridge between UDP and existing Unix socket IPC
- Key generation and port binding
- Roaming support (update client address on authenticated packets)
- Heartbeat and timeout detection

### Phase 3 — Remote Client (`zmx attach --remote`)

- SSH bootstrap: `ssh user@host zmx serve <session>`
- Parse key + port from stdout
- Close SSH, connect via UDP
- Reconnection logic: detect heartbeat loss → attempt reconnect → if buffer insufficient, request full state

### Phase 4 — Polish

- Predictive local echo (optional, high effort, high reward on bad networks)
- `zmx ls --remote` — list remote sessions
- Config file support for remote hosts

---

## 8. Key Design Decisions

| Decision | Options | Recommendation |
|---|---|---|
| **Encryption** | AES-GCM (hardware accel) vs XChaCha20-Poly1305 (Zig stdlib, safe nonces) | XChaCha20 — zero dependencies, safe nonce generation |
| **Data model** | State sync (Mosh) vs byte stream (ET) vs hybrid | Hybrid — stream bytes normally, full state on reconnect |
| **Gateway vs integrated** | Separate `zmx serve` process vs modify daemon | Gateway — isolates network code, daemon unchanged |
| **UDP port range** | Fixed port vs dynamic range | Dynamic (60000-61000 like Mosh), printed during bootstrap |
| **Heartbeat** | 100ms (tssh) vs 1s vs 3s (Mosh) | 1s — good balance of responsiveness and bandwidth |
| **Reconnect fallback** | Packet replay (ET) vs full state (zmx has this) vs both | Full state via `serializeTerminalState()` — simpler, zmx already does this perfectly |
| **Predictive echo** | Implement (major feature) vs skip | Skip for v1 — ~1000 lines in Mosh, requires careful testing |

---

## Sources

- [Mosh USENIX paper (PDF)](https://mosh.org/mosh-paper.pdf)
- [Mosh source code (GitHub)](https://github.com/mobile-shell/mosh)
- [MIT paper by Winstein & Balakrishnan](https://web.mit.edu/keithw/www/Winstein-Balakrishnan-Mosh.pdf)
- [Mosh official site](https://mosh.org/)
- [Eternal Terminal — How It Works](https://eternalterminal.dev/howitworks/)
- [ET protocol specification](https://github.com/MisterTea/EternalTerminal/blob/master/docs/protocol.md)
- [ET source code (GitHub)](https://github.com/MisterTea/EternalTerminal)
- [tssh documentation](https://trzsz.github.io/ssh.html)
- [tsshd source code (GitHub)](https://github.com/trzsz/tsshd)
- [trzsz-ssh source code (GitHub)](https://github.com/trzsz/trzsz-ssh)
- [Zig std.crypto.aead](https://ziglang.org/documentation/master/std/#std.crypto.aead)
