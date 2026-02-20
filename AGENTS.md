# zmosh Agent Guidelines

## Design Principles

1. **Simple yet robust** — Favor the simplest solution that handles failure gracefully. No over-engineering. If three lines of code work, don't build an abstraction.
2. **Idiomatic Zig** — Explicit over implicit. Comptime over runtime. Errors as values. No hidden control flow. Use the allocator pattern. Prefer `poll()` over threads.
3. **Don't reinvent the wheel** — Use Zig's standard library (`std.crypto`, `std.posix`, `std.net`) before writing custom code. If `std` solves the problem, use it.
4. **No unnecessary duplication** — Before writing new code, check if equivalent functionality already exists in the codebase. One source of truth for each concern.
5. **Zero external dependencies where possible** — zmosh currently has one external dep (`ghostty-vt`). Keep it minimal. Prefer `std.crypto.aead.xchacha20poly1305` over pulling in a C crypto library.
6. **Gateway architecture for network layer** — Network/crypto code lives in separate modules (`crypto.zig`, `udp.zig`, `serve.zig`). The daemon and its Unix socket IPC remain untouched. The `zmosh serve` gateway bridges UDP to the existing protocol.

## Architecture

- **Single binary** — `zmosh` serves as client, daemon, and gateway
- **Daemon-per-session** — Each session is an independent forked process
- **Event loop** — Single-threaded `poll()`, no threads
- **IPC** — Length-prefixed binary framing over Unix domain sockets (see `src/ipc.zig`)
- **Terminal state** — `ghostty_vt.Terminal` maintains full VT emulator with scrollback server-side
- **Re-attach** — `serializeTerminalState()` sends complete terminal snapshot on reconnect

## Commands

- **Build**: `zig build`
- **Test**: `zig build test`
- **Type check**: `zig build check`
- **Release**: `zig build release`

## What Not To Do

- Don't modify the daemon's core event loop or IPC protocol for network features — use the gateway pattern
- Don't add threads — the `poll()` loop is simple and correct
- Don't add external C dependencies — use Zig's stdlib
- Don't break the existing Unix socket path — local sessions must keep working unchanged
