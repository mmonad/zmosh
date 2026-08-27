const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp_mod = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");
const builtin = @import("builtin");

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_stdout_buf = 4 * 1024 * 1024;
const ack_delay_ns = 20 * std.time.ns_per_ms;

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
};

/// Parse a ZMX_CONNECT line: "ZMX_CONNECT udp-v2 <port> <base64_key>\n"
pub fn parseConnectLine(line: []const u8) !struct { port: u16, key: crypto.Key } {
    const trimmed = std.mem.trimRight(u8, line, "\r\n");
    var it = std.mem.splitScalar(u8, trimmed, ' ');

    const prefix = it.next() orelse return error.InvalidConnectLine;
    if (!std.mem.eql(u8, prefix, "ZMX_CONNECT")) return error.InvalidConnectLine;

    const proto = it.next() orelse return error.InvalidConnectLine;
    if (std.mem.eql(u8, proto, "udp")) return error.TransportVersionMismatch;
    if (!std.mem.eql(u8, proto, "udp-v2")) return error.UnsupportedProtocol;

    const port_str = it.next() orelse return error.InvalidConnectLine;
    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;

    const key_str = it.next() orelse return error.InvalidConnectLine;
    const key = crypto.keyFromBase64(key_str) catch return error.InvalidKey;

    return .{ .port = port, .key = key };
}

/// Bootstrap a remote session via SSH: ssh <host> zmosh serve <session>
/// Prepends common user bin dirs to PATH since SSH non-interactive sessions
/// often have a minimal PATH that excludes ~/.local/bin, ~/bin, etc.
fn appendShellQuoted(out: *std.ArrayList(u8), alloc: std.mem.Allocator, arg: []const u8) !void {
    try out.append(alloc, '\'');
    for (arg) |ch| {
        if (ch == '\'') try out.appendSlice(alloc, "'\\''") else try out.append(alloc, ch);
    }
    try out.append(alloc, '\'');
}

fn appendRemoteBinary(out: *std.ArrayList(u8), alloc: std.mem.Allocator, binary: []const u8) !void {
    const home_prefix = "$HOME/";
    if (std.mem.startsWith(u8, binary, home_prefix)) {
        try out.appendSlice(alloc, "\"$HOME\"/");
        try appendShellQuoted(out, alloc, binary[home_prefix.len..]);
        return;
    }
    try appendShellQuoted(out, alloc, binary);
}

pub fn connectRemote(
    alloc: std.mem.Allocator,
    host: []const u8,
    session: []const u8,
    command: ?[][]const u8,
) !RemoteSession {
    const term = posix.getenv("TERM") orelse "xterm-256color";
    const colorterm = posix.getenv("COLORTERM");
    const remote_binary = posix.getenv("ZMOSH_REMOTE_BIN") orelse "zmosh";
    var remote_cmd_buf: std.ArrayList(u8) = .empty;
    defer remote_cmd_buf.deinit(alloc);
    try remote_cmd_buf.appendSlice(alloc, "TERM=");
    try remote_cmd_buf.appendSlice(alloc, term);
    try remote_cmd_buf.append(alloc, ' ');
    if (colorterm) |ct| {
        try remote_cmd_buf.appendSlice(alloc, "COLORTERM=");
        try remote_cmd_buf.appendSlice(alloc, ct);
        try remote_cmd_buf.append(alloc, ' ');
    }
    try remote_cmd_buf.appendSlice(alloc, "PATH=\"$PATH:/opt/homebrew/bin:$HOME/bin:$HOME/.local/bin\" ");
    try appendRemoteBinary(&remote_cmd_buf, alloc, remote_binary);
    try remote_cmd_buf.appendSlice(alloc, " serve ");
    try appendShellQuoted(&remote_cmd_buf, alloc, session);
    if (command) |args| {
        for (args) |arg| {
            try remote_cmd_buf.append(alloc, ' ');
            try appendShellQuoted(&remote_cmd_buf, alloc, arg);
        }
    }
    const remote_cmd = try remote_cmd_buf.toOwnedSlice(alloc);
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

fn sendHeartbeat(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_recv: *const transport.OrderedRecv,
    last_ack_send_ns: *i64,
    ack_dirty: *bool,
    now: i64,
) !void {
    var pkt_buf: [1200]u8 = undefined;
    const pkt = try transport.buildUnreliable(
        .heartbeat,
        0,
        reliable_recv.ack(),
        reliable_recv.ackBits(),
        "",
        &pkt_buf,
    );
    try peer.send(sock, pkt);
    last_ack_send_ns.* = now;
    ack_dirty.* = false;
}

fn sendReliablePayload(
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.OrderedRecv,
    channel: transport.Channel,
    payload: []const u8,
) !void {
    _ = try reliable_send.queue(
        channel,
        payload,
        reliable_recv.ack(),
        reliable_recv.ackBits(),
    );
}

fn sendIpcReliable(
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.OrderedRecv,
    tag: ipc.Tag,
    payload: []const u8,
) !void {
    if (payload.len <= max_ipc_payload) {
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload, &buf);
        try sendReliablePayload(reliable_send, reliable_recv, .reliable_ipc, ipc_bytes);
        return;
    }

    var off: usize = 0;
    while (off < payload.len) {
        const end = @min(off + max_ipc_payload, payload.len);
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload[off..end], &buf);
        try sendReliablePayload(reliable_send, reliable_recv, .reliable_ipc, ipc_bytes);
        off = end;
    }
}

fn flushReliable(
    alloc: std.mem.Allocator,
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    now: i64,
) !void {
    var transmissions = try reliable_send.collectTransmissions(alloc, now, peer.rto_us());
    defer transmissions.deinit(alloc);
    for (transmissions.items) |packet| {
        peer.send(sock, packet) catch |err| {
            if (err == error.NoPeerAddress or err == error.WouldBlock) continue;
            return err;
        };
    }
}

const ReceiveAction = enum {
    none,
    stream_lost,
};

const RemoteReceiveState = struct {
    alloc: std.mem.Allocator,
    reliable_recv: transport.OrderedRecv,
    output_recv: transport.OutputRecvState,
    snapshot: transport.SnapshotAssembler,
    stdout_buf: std.ArrayList(u8),
    stdout_limit: usize = max_stdout_buf,
    restoring: bool,
    session_ended: bool = false,

    fn init(alloc: std.mem.Allocator, restore: bool) !RemoteReceiveState {
        var reliable_recv = try transport.OrderedRecv.init(alloc);
        errdefer reliable_recv.deinit();
        var output_recv = try transport.OutputRecvState.init(alloc);
        errdefer output_recv.deinit();
        var snapshot = try transport.SnapshotAssembler.init(alloc);
        errdefer snapshot.deinit();
        const stdout_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);

        return .{
            .alloc = alloc,
            .reliable_recv = reliable_recv,
            .output_recv = output_recv,
            .snapshot = snapshot,
            .stdout_buf = stdout_buf,
            .restoring = restore,
        };
    }

    fn deinit(self: *RemoteReceiveState) void {
        self.reliable_recv.deinit();
        self.output_recv.deinit();
        self.snapshot.deinit();
        self.stdout_buf.deinit(self.alloc);
    }

    fn beginRestore(self: *RemoteReceiveState) void {
        self.stdout_buf.clearRetainingCapacity();
        self.stdout_limit = max_stdout_buf;
        self.output_recv.clear();
        self.snapshot.reset();
        self.restoring = true;
    }

    fn appendStdout(self: *RemoteReceiveState, payload: []const u8) !bool {
        if (self.stdout_buf.items.len > self.stdout_limit or
            payload.len > self.stdout_limit - self.stdout_buf.items.len)
        {
            return false;
        }
        try self.stdout_buf.appendSlice(self.alloc, payload);
        return true;
    }

    fn consumeStdout(self: *RemoteReceiveState, len: usize) !void {
        try self.stdout_buf.replaceRange(self.alloc, 0, len, &[_]u8{});
        if (self.stdout_buf.items.len == 0) self.stdout_limit = max_stdout_buf;
    }

    fn handlePacket(self: *RemoteReceiveState, packet: transport.Packet, now: i64) !ReceiveAction {
        switch (packet.channel) {
            .heartbeat => return .none,
            .reliable_ipc, .control, .snapshot => {
                const recv_action = try self.reliable_recv.push(packet);
                if (recv_action == .stale) {
                    log.warn("reliable packet outside receive window seq={d}", .{packet.seq});
                }

                var result: ReceiveAction = .none;
                while (self.reliable_recv.popReady()) |ready| {
                    defer ready.deinit();
                    if (try self.handleReliablePayload(ready.channel, ready.payload) == .stream_lost) {
                        result = .stream_lost;
                    }
                }
                return result;
            },
            .output => {
                if (self.restoring) return .none;

                switch (try self.output_recv.onPacket(packet.seq, packet.payload, now)) {
                    .accept => {
                        var made_progress = false;
                        while (self.output_recv.popReady()) |payload| {
                            defer self.alloc.free(payload);
                            if (!try self.appendStdout(payload)) {
                                return .stream_lost;
                            }
                            made_progress = true;
                        }
                        self.output_recv.noteDrain(made_progress, now);
                    },
                    .gap => return .stream_lost,
                    .duplicate, .stale => {},
                }
                return .none;
            },
        }
    }

    fn handleReliablePayload(self: *RemoteReceiveState, channel: transport.Channel, payload: []const u8) !ReceiveAction {
        switch (channel) {
            .reliable_ipc => {
                var offset: usize = 0;
                while (offset < payload.len) {
                    const remaining = payload[offset..];
                    const msg_len = ipc.expectedLength(remaining) orelse break;
                    if (remaining.len < msg_len) break;

                    const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
                    const msg_payload = remaining[@sizeOf(ipc.Header)..msg_len];
                    if (hdr.tag == .Output and msg_payload.len > 0 and !self.restoring) {
                        if (!try self.appendStdout(msg_payload)) {
                            return .stream_lost;
                        }
                    } else if (hdr.tag == .SessionEnd) {
                        self.session_ended = true;
                    }
                    offset += msg_len;
                }
                return .none;
            },
            .snapshot => {
                const frame = transport.parseSnapshotFrame(payload) catch return .stream_lost;

                if (frame.kind == .begin) {
                    self.beginRestore();
                } else if (!self.snapshot.active) {
                    return .none;
                }

                const completed = self.snapshot.accept(frame) catch return .stream_lost;
                if (completed) |value| {
                    defer value.deinit(self.alloc);
                    self.stdout_limit = if (value.data.len > std.math.maxInt(usize) - max_stdout_buf)
                        std.math.maxInt(usize)
                    else
                        value.data.len + max_stdout_buf;
                    try self.stdout_buf.appendSlice(self.alloc, value.data);
                    self.output_recv.reset(value.resume_output_seq);
                    self.restoring = false;
                    log.info("installed terminal snapshot generation={d} bytes={d} output_seq={d}", .{
                        value.generation,
                        value.data.len,
                        value.resume_output_seq,
                    });
                }
                return .none;
            },
            .heartbeat, .output, .control => return .none,
        }
    }

    fn expireOutputGap(self: *RemoteReceiveState, now: i64, timeout_ns: i64) bool {
        return !self.restoring and self.output_recv.gapExpired(now, timeout_ns);
    }
};

fn outputReorderTimeoutNs(peer: *const udp_mod.Peer) i64 {
    const srtt_us = peer.srtt_us orelse 25_000;
    const timeout_us = std.math.clamp(2 * srtt_us, @as(i64, 50_000), @as(i64, 250_000));
    return timeout_us * std.time.ns_per_us;
}

/// Remote attach: connect to a remote zmx session via UDP.
pub fn remoteAttach(alloc: std.mem.Allocator, session: RemoteSession, restore: bool) !void {
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

    var reliable_send = try transport.ReliableSend.init(alloc);
    defer reliable_send.deinit();
    var receive_state = try RemoteReceiveState.init(alloc, restore);
    defer receive_state.deinit();

    // Set terminal to raw mode
    var orig_termios: c.termios = undefined;
    _ = c.tcgetattr(posix.STDIN_FILENO, &orig_termios);
    defer {
        _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSAFLUSH, &orig_termios);
    }

    var raw_termios = orig_termios;
    c.cfmakeraw(&raw_termios);
    raw_termios.c_cc[c.VLNEXT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VQUIT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VMIN] = 1;
    raw_termios.c_cc[c.VTIME] = 0;
    _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &raw_termios);

    setupSigwinchHandler();

    // Make stdin non-blocking
    const stdin_flags = try posix.fcntl(posix.STDIN_FILENO, posix.F.GETFL, 0);
    _ = try posix.fcntl(posix.STDIN_FILENO, posix.F.SETFL, stdin_flags | posix.SOCK.NONBLOCK);

    const config = udp_mod.Config{};
    var last_ack_send_ns: i64 = @intCast(std.time.nanoTimestamp());
    var ack_dirty = false;

    // Initialize dimensions, requesting a snapshot only for --restore.
    const size = getTerminalSize();
    var init_buf: [64]u8 = undefined;
    const init_tag: ipc.Tag = if (restore) .Restore else .Init;
    const init_ipc = transport.buildIpcBytes(init_tag, std.mem.asBytes(&size), &init_buf);
    try sendReliablePayload(&reliable_send, &receive_state.reliable_recv, .reliable_ipc, init_ipc);

    while (true) {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        const reorder_timeout_ns = outputReorderTimeoutNs(&peer);

        if (receive_state.expireOutputGap(now, reorder_timeout_ns)) {
            return error.OutputStreamLost;
        }

        // Check SIGWINCH
        if (sigwinch_received.swap(false, .acq_rel)) {
            const new_size = getTerminalSize();
            try sendIpcReliable(&reliable_send, &receive_state.reliable_recv, .Resize, std.mem.asBytes(&new_size));
        }

        // Send new reliable packets and retransmit due packets within the
        // bounded flight window.
        try flushReliable(alloc, &peer, &udp_sock, &reliable_send, now);

        // Ack heartbeat + keepalive heartbeat.
        if (ack_dirty and (now - last_ack_send_ns) >= ack_delay_ns) {
            sendHeartbeat(&peer, &udp_sock, &receive_state.reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
        } else if (peer.shouldSendHeartbeat(now, config)) {
            sendHeartbeat(&peer, &udp_sock, &receive_state.reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
        }

        // State check
        const state = peer.updateState(now, config);
        if (state == .dead) {
            return error.ConnectionLost;
        }

        // Build poll fds
        var poll_fds: [3]posix.pollfd = undefined;
        var poll_count: usize = 2;
        poll_fds[0] = .{ .fd = posix.STDIN_FILENO, .events = posix.POLL.IN, .revents = 0 };
        poll_fds[1] = .{ .fd = udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };
        if (receive_state.stdout_buf.items.len > 0) {
            poll_fds[2] = .{ .fd = posix.STDOUT_FILENO, .events = posix.POLL.OUT, .revents = 0 };
            poll_count = 3;
        }

        var poll_timeout: i64 = @min(@as(i64, config.heartbeat_interval_ms), 500);
        if (reliable_send.hasPending()) {
            const rto_ms = @divFloor(peer.rto_us(), 1000);
            poll_timeout = @min(poll_timeout, @max(@as(i64, 1), rto_ms));
        }
        if (ack_dirty) poll_timeout = @min(poll_timeout, @as(i64, 20));
        if (!receive_state.restoring) {
            if (receive_state.output_recv.gapRemainingNs(now, reorder_timeout_ns)) |remaining_ns| {
                const remaining_ms = @divFloor(remaining_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms);
                poll_timeout = @min(poll_timeout, remaining_ms);
            }
        }

        _ = posix.poll(poll_fds[0..poll_count], @intCast(poll_timeout)) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        // STDIN → reliable IPC over UDP
        if (poll_fds[0].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR) != 0) {
            var input_raw: [4096]u8 = undefined;
            const n_opt: ?usize = posix.read(posix.STDIN_FILENO, &input_raw) catch |err| blk: {
                if (err == error.WouldBlock) break :blk null;
                return err;
            };
            if (n_opt) |n| {
                if (n > 0) {
                    if (input_raw[0] == 0x1C or isKittyCtrlBackslash(input_raw[0..n])) {
                        try sendIpcReliable(&reliable_send, &receive_state.reliable_recv, .Detach, "");
                        try flushReliable(alloc, &peer, &udp_sock, &reliable_send, now);
                        return;
                    }
                    try sendIpcReliable(&reliable_send, &receive_state.reliable_recv, .Input, input_raw[0..n]);
                } else {
                    try sendIpcReliable(&reliable_send, &receive_state.reliable_recv, .Detach, "");
                    try flushReliable(alloc, &peer, &udp_sock, &reliable_send, now);
                    return; // EOF on stdin
                }
            }
        }

        // UDP recv → decode transport packets
        if (poll_fds[1].revents & posix.POLL.IN != 0) {
            while (true) {
                var decrypt_buf: [9000]u8 = undefined;
                const recv_result = try peer.recv(&udp_sock, &decrypt_buf);
                const result = recv_result orelse break;

                const packet = transport.parsePacket(result.data) catch continue;
                reliable_send.ack(packet.ack, packet.ack_bits);

                if (packet.channel == .reliable_ipc or packet.channel == .control or packet.channel == .snapshot) {
                    ack_dirty = true;
                }
                if (try receive_state.handlePacket(packet, now) == .stream_lost) {
                    return error.OutputStreamLost;
                }
            }
        }

        // Flush stdout
        if (poll_count == 3 and poll_fds[2].revents & posix.POLL.OUT != 0) {
            if (receive_state.stdout_buf.items.len > 0) {
                const written = posix.write(posix.STDOUT_FILENO, receive_state.stdout_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk 0;
                    return err;
                };
                if (written > 0) {
                    try receive_state.consumeStdout(written);
                }
            }
        }

        if (receive_state.session_ended) {
            if (receive_state.stdout_buf.items.len > 0) {
                _ = posix.write(posix.STDOUT_FILENO, receive_state.stdout_buf.items) catch {};
            }
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseConnectLine valid" {
    const result = try parseConnectLine("ZMX_CONNECT udp-v2 60042 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    try std.testing.expect(result.port == 60042);
}

test "parseConnectLine invalid prefix" {
    try std.testing.expectError(error.InvalidConnectLine, parseConnectLine("INVALID udp 60042 key\n"));
}

test "parseConnectLine unsupported protocol" {
    try std.testing.expectError(error.UnsupportedProtocol, parseConnectLine("ZMX_CONNECT tcp 60042 key\n"));
}

test "parseConnectLine rejects legacy transport version" {
    try std.testing.expectError(error.TransportVersionMismatch, parseConnectLine("ZMX_CONNECT udp 60042 key\n"));
}

test "remote bootstrap honors a safely quoted explicit binary" {
    const alloc = std.testing.allocator;
    var command: std.ArrayList(u8) = .empty;
    defer command.deinit(alloc);

    try appendRemoteBinary(&command, alloc, "$HOME/.local/bin/zmosh");
    try std.testing.expectEqualStrings("\"$HOME\"/'.local/bin/zmosh'", command.items);

    command.clearRetainingCapacity();
    try appendRemoteBinary(&command, alloc, "/tmp/zmosh test/zmosh");
    try std.testing.expectEqualStrings("'/tmp/zmosh test/zmosh'", command.items);
}

test "remote receive forwards reliable output without an automatic restore" {
    const alloc = std.testing.allocator;
    var state = try RemoteReceiveState.init(alloc, false);
    defer state.deinit();

    var ipc_buf: [transport.max_payload_len]u8 = undefined;
    const ipc_bytes = transport.buildIpcBytes(.Output, "raw-output", &ipc_buf);
    try std.testing.expect(try state.handlePacket(.{
        .channel = .reliable_ipc,
        .seq = 1,
        .ack = 0,
        .ack_bits = 0,
        .payload = ipc_bytes,
    }, 1) == .none);

    try std.testing.expect(!state.restoring);
    try std.testing.expectEqualStrings("raw-output", state.stdout_buf.items);
}

test "remote receive installs an explicitly requested snapshot before ordered output" {
    const alloc = std.testing.allocator;
    var state = try RemoteReceiveState.init(alloc, true);
    defer state.deinit();

    // Incremental output from the pre-snapshot generation is suppressed.
    try std.testing.expect(try state.handlePacket(.{
        .channel = .output,
        .seq = 1,
        .ack = 0,
        .ack_bits = 0,
        .payload = "stale",
    }, 1) == .none);
    try std.testing.expectEqual(@as(usize, 0), state.stdout_buf.items.len);

    const snapshot_bytes = "complete-snapshot";
    var frame_buf: [transport.max_payload_len]u8 = undefined;
    const frames = [_]transport.SnapshotFrame{
        .{
            .kind = .begin,
            .generation = 7,
            .total_len = snapshot_bytes.len,
            .offset = 0,
            .resume_output_seq = 10,
            .data = "",
        },
        .{
            .kind = .chunk,
            .generation = 7,
            .total_len = snapshot_bytes.len,
            .offset = 0,
            .resume_output_seq = 10,
            .data = snapshot_bytes,
        },
        .{
            .kind = .end,
            .generation = 7,
            .total_len = snapshot_bytes.len,
            .offset = snapshot_bytes.len,
            .resume_output_seq = 10,
            .data = "",
        },
    };

    for (frames, 1..) |frame, seq| {
        const payload = try transport.buildSnapshotFrame(frame, &frame_buf);
        try std.testing.expect(try state.handlePacket(.{
            .channel = .snapshot,
            .seq = @intCast(seq),
            .ack = 0,
            .ack_bits = 0,
            .payload = payload,
        }, @intCast(seq)) == .none);

        if (frame.kind != .end) {
            try std.testing.expect(state.restoring);
            try std.testing.expectEqual(@as(usize, 0), state.stdout_buf.items.len);
        }
    }

    try std.testing.expect(!state.restoring);
    try std.testing.expectEqualStrings(snapshot_bytes, state.stdout_buf.items);

    // A modest output reordering is buffered and emitted in sequence order.
    try std.testing.expect(try state.handlePacket(.{
        .channel = .output,
        .seq = 11,
        .ack = 0,
        .ack_bits = 0,
        .payload = "B",
    }, 20) == .none);
    try std.testing.expectEqualStrings(snapshot_bytes, state.stdout_buf.items);

    try std.testing.expect(try state.handlePacket(.{
        .channel = .output,
        .seq = 10,
        .ack = 0,
        .ack_bits = 0,
        .payload = "A",
    }, 21) == .none);
    try std.testing.expectEqualStrings(snapshot_bytes ++ "AB", state.stdout_buf.items);
}

test "remote receive reports a reorder gap without synthesizing a restore" {
    const alloc = std.testing.allocator;
    var state = try RemoteReceiveState.init(alloc, false);
    defer state.deinit();
    state.output_recv.reset(1);
    try state.stdout_buf.appendSlice(alloc, "stable");

    try std.testing.expect(try state.handlePacket(.{
        .channel = .output,
        .seq = 2,
        .ack = 0,
        .ack_bits = 0,
        .payload = "later",
    }, 100) == .none);
    try std.testing.expectEqualStrings("stable", state.stdout_buf.items);
    try std.testing.expect(!state.expireOutputGap(149, 50));
    try std.testing.expect(state.expireOutputGap(150, 50));
    try std.testing.expect(!state.restoring);
    try std.testing.expectEqualStrings("stable", state.stdout_buf.items);
}

test "reliable terminal output survives loss and reordering without resync" {
    const alloc = std.testing.allocator;
    var state = try RemoteReceiveState.init(alloc, true);
    defer state.deinit();
    var send = try transport.ReliableSend.init(alloc);
    defer send.deinit();

    const snapshot_range = try transport.queueSnapshot(
        &send,
        1,
        "initial-",
        1,
        0,
        0,
    );

    for ([_][]const u8{ "one-", "two-", "three" }) |output| {
        var ipc_buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(.Output, output, &ipc_buf);
        _ = try send.queue(.reliable_ipc, ipc_bytes, 0, 0);
    }

    const dropped_seq = snapshot_range.last + 2;
    var dropped_once = false;
    var stream_losses: usize = 0;
    var now: i64 = 1;
    var rounds: usize = 0;
    while (send.hasPending() and rounds < 100) : (rounds += 1) {
        var batch = try send.collectTransmissions(alloc, now, 1000);
        defer batch.deinit(alloc);

        // Deliver each flight backwards and discard one output packet on its
        // first transmission. Ordered reliable receive must stall, then emit
        // every terminal byte exactly once after the retry arrives.
        var i = batch.items.len;
        while (i > 0) {
            i -= 1;
            const packet = try transport.parsePacket(batch.items[i]);
            if (packet.seq == dropped_seq and !dropped_once) {
                dropped_once = true;
                continue;
            }
            if (try state.handlePacket(packet, now) == .stream_lost) {
                stream_losses += 1;
            }
        }

        send.ack(state.reliable_recv.ack(), state.reliable_recv.ackBits());
        now += 2 * std.time.ns_per_ms;
    }

    try std.testing.expect(dropped_once);
    try std.testing.expect(!send.hasPending());
    try std.testing.expect(rounds < 100);
    try std.testing.expectEqual(@as(usize, 0), stream_losses);
    try std.testing.expect(!state.restoring);
    try std.testing.expectEqualStrings("initial-one-two-three", state.stdout_buf.items);
}
