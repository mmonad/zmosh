const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp_mod = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");
const builtin = @import("builtin");

const c = switch (builtin.os.tag) {
    .macos => @cImport({
        @cInclude("sys/ioctl.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
    .freebsd => @cImport({
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
    else => @cImport({
        @cInclude("sys/ioctl.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
};

const log = std.log.scoped(.remote);

pub const RemoteSession = struct {
    host: []const u8,
    port: u16,
    key: crypto.Key,
    transport: transport.Kind,
};

/// Parse a ZMX_CONNECT line: "ZMX_CONNECT <transport> <port> <base64_key>\n"
pub fn parseConnectLine(line: []const u8) !struct { transport: transport.Kind, port: u16, key: crypto.Key } {
    const trimmed = std.mem.trimRight(u8, line, "\r\n");
    var it = std.mem.splitScalar(u8, trimmed, ' ');

    const prefix = it.next() orelse return error.InvalidConnectLine;
    if (!std.mem.eql(u8, prefix, "ZMX_CONNECT")) return error.InvalidConnectLine;

    const proto = it.next() orelse return error.InvalidConnectLine;
    const kind = transport.Kind.parse(proto) orelse return error.UnsupportedProtocol;

    const port_str = it.next() orelse return error.InvalidConnectLine;
    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;

    const key_str = it.next() orelse return error.InvalidConnectLine;
    const key = crypto.keyFromBase64(key_str) catch return error.InvalidKey;

    return .{ .transport = kind, .port = port, .key = key };
}

/// Bootstrap a remote session via SSH: ssh <host> zmosh serve <session>
/// Prepends common user bin dirs to PATH since SSH non-interactive sessions
/// often have a minimal PATH that excludes ~/.local/bin, ~/bin, etc.
pub fn connectRemote(
    alloc: std.mem.Allocator,
    host: []const u8,
    session: []const u8,
    kind: transport.Kind,
) !RemoteSession {
    const term = posix.getenv("TERM") orelse "xterm-256color";
    const colorterm = posix.getenv("COLORTERM");
    const serve_cmd = if (kind == .udp)
        try std.fmt.allocPrint(alloc, "zmosh serve {s}", .{session})
    else
        try std.fmt.allocPrint(alloc, "zmosh serve --transport {s} {s}", .{ kind.asString(), session });
    defer alloc.free(serve_cmd);

    const remote_cmd = if (colorterm) |ct|
        try std.fmt.allocPrint(
            alloc,
            "TERM={s} COLORTERM={s} PATH=\"$HOME/.local/bin:$HOME/bin:$HOME/.cargo/bin:$PATH\" {s}",
            .{ term, ct, serve_cmd },
        )
    else
        try std.fmt.allocPrint(
            alloc,
            "TERM={s} PATH=\"$HOME/.local/bin:$HOME/bin:$HOME/.cargo/bin:$PATH\" {s}",
            .{ term, serve_cmd },
        );
    defer alloc.free(remote_cmd);
    const argv = [_][]const u8{ "ssh", host, "--", remote_cmd };
    var child = std.process.Child.init(&argv, alloc);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Inherit;
    try child.spawn();

    // Read stdout looking for ZMX_CONNECT line
    const stdout = child.stdout.?;
    var buf: [512]u8 = undefined;
    var total: usize = 0;

    while (total < buf.len) {
        const n = stdout.read(buf[total..]) catch |err| {
            log.err("failed to read SSH stdout: {s}", .{@errorName(err)});
            return error.SshReadFailed;
        };
        if (n == 0) break;
        total += n;

        // Check if we have a complete line
        if (std.mem.indexOf(u8, buf[0..total], "\n")) |_| break;
    }

    if (total == 0) {
        _ = child.wait() catch {};
        return error.SshNoOutput;
    }

    const result = parseConnectLine(buf[0..total]) catch |err| {
        log.err("failed to parse connect line: {s}", .{@errorName(err)});
        _ = child.wait() catch {};
        return err;
    };
    if (result.transport != kind) {
        log.err("transport mismatch requested={s} got={s}", .{ kind.asString(), result.transport.asString() });
        _ = child.wait() catch {};
        return error.TransportMismatch;
    }

    // Close our end of the pipes — we have the connect info.
    // Don't wait for SSH to exit: the remote gateway runs indefinitely.
    // SSH will be killed when we exit or will linger harmlessly.
    if (child.stdin) |f| {
        f.close();
        child.stdin = null;
    }
    if (child.stdout) |f| {
        f.close();
        child.stdout = null;
    }

    return .{
        .host = host,
        .port = result.port,
        .key = result.key,
        .transport = result.transport,
    };
}

var sigwinch_received: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn handleSigwinch(_: i32, _: *const posix.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    sigwinch_received.store(true, .release);
}

fn setupSigwinchHandler() void {
    const act: posix.Sigaction = .{
        .handler = .{ .sigaction = handleSigwinch },
        .mask = posix.sigemptyset(),
        .flags = posix.SA.SIGINFO,
    };
    posix.sigaction(posix.SIG.WINCH, &act, null);
}

fn getTerminalSize() ipc.Resize {
    var ws: c.struct_winsize = undefined;
    if (c.ioctl(posix.STDOUT_FILENO, c.TIOCGWINSZ, &ws) == 0 and ws.ws_row > 0 and ws.ws_col > 0) {
        return .{ .rows = ws.ws_row, .cols = ws.ws_col };
    }
    return .{ .rows = 24, .cols = 80 };
}

/// Detects Kitty keyboard protocol escape sequence for Ctrl+\
fn isKittyCtrlBackslash(buf: []const u8) bool {
    return std.mem.indexOf(u8, buf, "\x1b[92;5u") != null or
        std.mem.indexOf(u8, buf, "\x1b[92;5:1u") != null;
}

/// Remote attach: connect to a remote zmx session via UDP.
pub fn remoteAttach(alloc: std.mem.Allocator, session: RemoteSession) !void {
    switch (session.transport) {
        .udp => return remoteAttachUdp(alloc, session),
        .quic => {
            log.err("QUIC transport is experimental and not implemented yet", .{});
            return error.TransportNotImplemented;
        },
    }
}

fn remoteAttachUdp(alloc: std.mem.Allocator, session: RemoteSession) !void {
    // Resolve host address — try numeric IP first, fall back to DNS
    const addr = std.net.Address.resolveIp(session.host, session.port) catch blk: {
        const list = try std.net.getAddressList(alloc, session.host, session.port);
        defer list.deinit();
        if (list.addrs.len == 0) return error.HostNotFound;
        break :blk list.addrs[0];
    };

    // Create UDP socket — bind ephemeral port (OS picks)
    const sock_fd = try posix.socket(
        addr.any.family,
        posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
        0,
    );
    var udp_sock = udp_mod.UdpSocket{ .fd = sock_fd, .bound_port = 0 };
    defer udp_sock.close();

    // Create peer
    var peer = udp_mod.Peer.init(session.key, .to_server);
    peer.addr = addr;

    // Set terminal to raw mode
    var orig_termios: c.termios = undefined;
    _ = c.tcgetattr(posix.STDIN_FILENO, &orig_termios);
    defer {
        _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSAFLUSH, &orig_termios);
        const restore_seq = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l" ++
            "\x1b[?2004l\x1b[?1004l\x1b[?1049l" ++
            "\x1b[?25h";
        _ = posix.write(posix.STDOUT_FILENO, restore_seq) catch {};
    }

    var raw_termios = orig_termios;
    c.cfmakeraw(&raw_termios);
    raw_termios.c_cc[c.VLNEXT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VQUIT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VMIN] = 1;
    raw_termios.c_cc[c.VTIME] = 0;
    _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &raw_termios);

    // Clear screen
    _ = try posix.write(posix.STDOUT_FILENO, "\x1b[2J\x1b[H");

    setupSigwinchHandler();

    // Make stdin non-blocking
    const stdin_flags = try posix.fcntl(posix.STDIN_FILENO, posix.F.GETFL, 0);
    _ = try posix.fcntl(posix.STDIN_FILENO, posix.F.SETFL, stdin_flags | posix.SOCK.NONBLOCK);

    // Send Init message with terminal size
    const size = getTerminalSize();
    var init_buf: [128]u8 = undefined;
    const init_ipc = buildIpcBytes(.Init, std.mem.asBytes(&size), &init_buf);
    try peer.send(&udp_sock, init_ipc);

    const config = udp_mod.Config{};
    var stdout_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
    defer stdout_buf.deinit(alloc);
    var was_disconnected = false;
    var session_ended = false;

    while (true) {
        const now: i64 = @intCast(std.time.nanoTimestamp());

        // Check SIGWINCH
        if (sigwinch_received.swap(false, .acq_rel)) {
            const new_size = getTerminalSize();
            var resize_buf: [128]u8 = undefined;
            const resize_ipc = buildIpcBytes(.Resize, std.mem.asBytes(&new_size), &resize_buf);
            peer.send(&udp_sock, resize_ipc) catch {};
        }

        // Heartbeat
        if (peer.shouldSendHeartbeat(now, config)) {
            peer.send(&udp_sock, "") catch {};
        }

        // State check
        const state = peer.updateState(now, config);
        if (state == .dead) {
            _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: connection lost permanently\r\n") catch {};
            return;
        }
        if (state == .disconnected and !was_disconnected) {
            // Show disconnected status
            _ = posix.write(posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b[7mzmx: connection lost — waiting to reconnect...\x1b[27m\x1b8") catch {};
            was_disconnected = true;
        } else if (state == .connected and was_disconnected) {
            // Clear status line
            _ = posix.write(posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b8") catch {};
            was_disconnected = false;
        }

        // Build poll fds
        var poll_fds: [3]posix.pollfd = undefined;
        var poll_count: usize = 2;
        poll_fds[0] = .{ .fd = posix.STDIN_FILENO, .events = posix.POLL.IN, .revents = 0 };
        poll_fds[1] = .{ .fd = udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };
        if (stdout_buf.items.len > 0) {
            poll_fds[2] = .{ .fd = posix.STDOUT_FILENO, .events = posix.POLL.OUT, .revents = 0 };
            poll_count = 3;
        }

        const poll_timeout: i32 = @intCast(@min(config.heartbeat_interval_ms, 500));
        _ = posix.poll(poll_fds[0..poll_count], poll_timeout) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        // STDIN → encrypt → send via UDP
        if (poll_fds[0].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR) != 0) {
            var input_raw: [4096]u8 = undefined;
            const n_opt: ?usize = posix.read(posix.STDIN_FILENO, &input_raw) catch |err| blk: {
                if (err == error.WouldBlock) break :blk null;
                return err;
            };
            if (n_opt) |n| {
                if (n > 0) {
                    if (input_raw[0] == 0x1C or isKittyCtrlBackslash(input_raw[0..n])) {
                        // Detach
                        var detach_buf: [128]u8 = undefined;
                        const detach_ipc = buildIpcBytes(.Detach, "", &detach_buf);
                        peer.send(&udp_sock, detach_ipc) catch {};
                        return;
                    }
                    var ipc_buf: [4096 + @sizeOf(ipc.Header)]u8 = undefined;
                    const input_ipc = buildIpcBytes(.Input, input_raw[0..n], &ipc_buf);
                    peer.send(&udp_sock, input_ipc) catch {};
                } else {
                    return; // EOF on stdin
                }
            }
        }

        // UDP recv → decrypt → extract IPC → write to stdout
        if (poll_fds[1].revents & posix.POLL.IN != 0) {
            var decrypt_buf: [9000]u8 = undefined;
            if (try peer.recv(&udp_sock, &decrypt_buf)) |result| {
                if (result.data.len >= @sizeOf(ipc.Header)) {
                    // Parse IPC messages from the decrypted plaintext
                    var offset: usize = 0;
                    while (offset < result.data.len) {
                        const remaining = result.data[offset..];
                        const msg_len = ipc.expectedLength(remaining) orelse break;
                        if (remaining.len < msg_len) break;

                        const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
                        const payload = remaining[@sizeOf(ipc.Header)..msg_len];

                        if (hdr.tag == .Output and payload.len > 0) {
                            try stdout_buf.appendSlice(alloc, payload);
                        } else if (hdr.tag == .SessionEnd) {
                            session_ended = true;
                        }
                        offset += msg_len;
                    }
                }
            }
        }

        // Flush stdout
        if (poll_count == 3 and poll_fds[2].revents & posix.POLL.OUT != 0) {
            if (stdout_buf.items.len > 0) {
                const written = posix.write(posix.STDOUT_FILENO, stdout_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk 0;
                    return err;
                };
                if (written > 0) {
                    try stdout_buf.replaceRange(alloc, 0, written, &[_]u8{});
                }
            }
        }

        if (session_ended) {
            // Flush any remaining output before exiting
            if (stdout_buf.items.len > 0) {
                _ = posix.write(posix.STDOUT_FILENO, stdout_buf.items) catch {};
            }
            _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: remote session ended\r\n") catch {};
            return;
        }
    }
}

/// Build raw IPC bytes (header + payload) into a buffer.
fn buildIpcBytes(tag: ipc.Tag, payload: []const u8, buf: []u8) []const u8 {
    const header = ipc.Header{ .tag = tag, .len = @intCast(payload.len) };
    const hdr_bytes = std.mem.asBytes(&header);
    const total = @sizeOf(ipc.Header) + payload.len;
    std.debug.assert(buf.len >= total);
    @memcpy(buf[0..@sizeOf(ipc.Header)], hdr_bytes);
    if (payload.len > 0) {
        @memcpy(buf[@sizeOf(ipc.Header)..total], payload);
    }
    return buf[0..total];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseConnectLine valid" {
    const result = try parseConnectLine("ZMX_CONNECT udp 60042 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    try std.testing.expect(result.transport == .udp);
    try std.testing.expect(result.port == 60042);
}

test "parseConnectLine quic" {
    const result = try parseConnectLine("ZMX_CONNECT quic 60042 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    try std.testing.expect(result.transport == .quic);
    try std.testing.expect(result.port == 60042);
}

test "parseConnectLine invalid prefix" {
    try std.testing.expectError(error.InvalidConnectLine, parseConnectLine("INVALID udp 60042 key\n"));
}

test "parseConnectLine unsupported protocol" {
    try std.testing.expectError(error.UnsupportedProtocol, parseConnectLine("ZMX_CONNECT tcp 60042 key\n"));
}

test "buildIpcBytes round-trip" {
    var buf: [128]u8 = undefined;
    const payload = "hello";
    const ipc_bytes = buildIpcBytes(.Input, payload, &buf);

    try std.testing.expect(ipc_bytes.len == @sizeOf(ipc.Header) + payload.len);
    const hdr = std.mem.bytesToValue(ipc.Header, ipc_bytes[0..@sizeOf(ipc.Header)]);
    try std.testing.expect(hdr.tag == .Input);
    try std.testing.expect(hdr.len == payload.len);
    try std.testing.expectEqualStrings(payload, ipc_bytes[@sizeOf(ipc.Header)..]);
}
