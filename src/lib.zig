const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp_mod = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_input_len = 1024 * 1024;
const ack_delay_ns = 20 * std.time.ns_per_ms;
const alloc = std.heap.page_allocator;

// Silence all logging in library mode.
pub const std_options: std.Options = .{
    .logFn = struct {
        fn f(
            comptime _: std.log.Level,
            comptime _: anytype,
            comptime _: []const u8,
            _: anytype,
        ) void {}
    }.f,
};

// ---------------------------------------------------------------------------
// C API types
// ---------------------------------------------------------------------------

pub const Status = enum(c_int) {
    ok = 0,
    err_resolve = 1,
    err_socket = 2,
    err_invalid_key = 3,
    err_disconnected = 4,
    err_dead = 5,
    err_poll = 6,
    err_null = 7,
    err_send = 8,
    err_too_large = 9,
    err_output_stream_lost = 10,
};

pub const State = enum(c_int) {
    connected = 0,
    disconnected = 1,
    dead = 2,
};

pub const OutputFn = *const fn (?*anyopaque, [*]const u8, u32) callconv(.c) void;
pub const StateFn = *const fn (?*anyopaque, State) callconv(.c) void;
pub const SessionEndFn = *const fn (?*anyopaque) callconv(.c) void;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

const Session = struct {
    udp_sock: udp_mod.UdpSocket,
    peer: udp_mod.Peer,
    config: udp_mod.Config,

    reliable_send: transport.ReliableSend,
    reliable_recv: transport.OrderedRecv,
    output_recv: transport.OutputRecvState,
    snapshot: transport.SnapshotAssembler,
    restoring: bool,

    last_ack_send_ns: i64,
    ack_dirty: bool,
    output_cb: OutputFn,
    state_cb: ?StateFn,
    end_cb: ?SessionEndFn,
    ctx: ?*anyopaque,

    last_state: udp_mod.PeerState,
    session_ended: bool,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sendHeartbeat(s: *Session, now: i64) !void {
    var pkt_buf: [1200]u8 = undefined;
    const pkt = try transport.buildUnreliable(
        .heartbeat,
        0,
        s.reliable_recv.ack(),
        s.reliable_recv.ackBits(),
        "",
        &pkt_buf,
    );
    try s.peer.send(&s.udp_sock, pkt);
    s.last_ack_send_ns = now;
    s.ack_dirty = false;
}

fn sendReliablePayload(s: *Session, channel: transport.Channel, payload: []const u8) !void {
    _ = try s.reliable_send.queue(
        channel,
        payload,
        s.reliable_recv.ack(),
        s.reliable_recv.ackBits(),
    );
}

fn sendIpcReliable(s: *Session, tag: ipc.Tag, payload: []const u8) !void {
    if (payload.len <= max_ipc_payload) {
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload, &buf);
        try sendReliablePayload(s, .reliable_ipc, ipc_bytes);
        return;
    }

    var off: usize = 0;
    while (off < payload.len) {
        const end = @min(off + max_ipc_payload, payload.len);
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload[off..end], &buf);
        try sendReliablePayload(s, .reliable_ipc, ipc_bytes);
        off = end;
    }
}

fn flushReliable(s: *Session, now: i64) !void {
    var transmissions = try s.reliable_send.collectTransmissions(alloc, now, s.peer.rto_us());
    defer transmissions.deinit(alloc);
    for (transmissions.items) |packet| {
        s.peer.send(&s.udp_sock, packet) catch |err| {
            if (err == error.NoPeerAddress or err == error.WouldBlock) continue;
            return err;
        };
    }
}

fn beginRestore(s: *Session) void {
    s.output_recv.clear();
    s.snapshot.reset();
    s.restoring = true;
}

fn handleReliablePayload(s: *Session, channel: transport.Channel, payload: []const u8) !void {
    switch (channel) {
        .reliable_ipc => {
            var offset: usize = 0;
            while (offset < payload.len) {
                const remaining = payload[offset..];
                const msg_len = ipc.expectedLength(remaining) orelse break;
                if (remaining.len < msg_len) break;

                const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
                const msg_payload = remaining[@sizeOf(ipc.Header)..msg_len];
                if (hdr.tag == .Output and msg_payload.len > 0 and !s.restoring) {
                    s.output_cb(s.ctx, msg_payload.ptr, @intCast(msg_payload.len));
                } else if (hdr.tag == .SessionEnd) {
                    s.session_ended = true;
                    if (s.end_cb) |cb| cb(s.ctx);
                }
                offset += msg_len;
            }
        },
        .snapshot => {
            const frame = transport.parseSnapshotFrame(payload) catch return error.OutputStreamLost;
            if (frame.kind == .begin) {
                beginRestore(s);
            } else if (!s.snapshot.active) {
                return;
            }

            const completed = s.snapshot.accept(frame) catch return error.OutputStreamLost;
            if (completed) |value| {
                defer value.deinit(alloc);
                if (value.data.len > 0) {
                    s.output_cb(s.ctx, value.data.ptr, @intCast(value.data.len));
                }
                s.output_recv.reset(value.resume_output_seq);
                s.restoring = false;
            }
        },
        .heartbeat, .output, .control => {},
    }
}

// ---------------------------------------------------------------------------
// Exported C API
// ---------------------------------------------------------------------------

export fn zmosh_connect(
    host: ?[*:0]const u8,
    port: u16,
    key_base64: ?[*:0]const u8,
    rows: u16,
    cols: u16,
    output_cb: ?OutputFn,
    state_cb: ?StateFn,
    end_cb: ?SessionEndFn,
    ctx: ?*anyopaque,
    status: ?*Status,
) ?*Session {
    const set_status = struct {
        fn f(s: ?*Status, v: Status) void {
            if (s) |p| p.* = v;
        }
    }.f;

    const host_str = host orelse {
        set_status(status, .err_null);
        return null;
    };
    const key_str = key_base64 orelse {
        set_status(status, .err_null);
        return null;
    };
    const cb = output_cb orelse {
        set_status(status, .err_null);
        return null;
    };

    // Decode key
    const key = crypto.keyFromBase64(std.mem.span(key_str)) catch {
        set_status(status, .err_invalid_key);
        return null;
    };

    // Resolve address
    const addr = std.net.Address.resolveIp(std.mem.span(host_str), port) catch blk: {
        const list = std.net.getAddressList(std.heap.page_allocator, std.mem.span(host_str), port) catch {
            set_status(status, .err_resolve);
            return null;
        };
        defer list.deinit();
        if (list.addrs.len == 0) {
            set_status(status, .err_resolve);
            return null;
        }
        break :blk list.addrs[0];
    };

    // Create UDP socket — ephemeral port
    const sock_fd = posix.socket(
        addr.any.family,
        posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
        0,
    ) catch {
        set_status(status, .err_socket);
        return null;
    };
    var udp_sock = udp_mod.UdpSocket{ .fd = sock_fd, .bound_port = 0 };

    // Init peer
    var peer = udp_mod.Peer.init(key, .to_server);
    peer.addr = addr;

    const now: i64 = @intCast(std.time.nanoTimestamp());
    var reliable_send = transport.ReliableSend.init(alloc) catch {
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    var reliable_recv = transport.OrderedRecv.init(alloc) catch {
        reliable_send.deinit();
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    var output_recv = transport.OutputRecvState.init(alloc) catch {
        reliable_recv.deinit();
        reliable_send.deinit();
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    var snapshot = transport.SnapshotAssembler.init(alloc) catch {
        output_recv.deinit();
        reliable_recv.deinit();
        reliable_send.deinit();
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };

    // Initialize dimensions without requesting a synthetic terminal repaint.
    const size = ipc.Resize{ .rows = rows, .cols = cols };
    var init_buf: [64]u8 = undefined;
    const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&size), &init_buf);

    _ = reliable_send.queue(.reliable_ipc, init_ipc, 0, 0) catch {
        snapshot.deinit();
        output_recv.deinit();
        reliable_recv.deinit();
        reliable_send.deinit();
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };

    // Allocate session
    const session = alloc.create(Session) catch {
        snapshot.deinit();
        output_recv.deinit();
        reliable_recv.deinit();
        reliable_send.deinit();
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    session.* = .{
        .udp_sock = udp_sock,
        .peer = peer,
        .config = .{},
        .reliable_send = reliable_send,
        .reliable_recv = reliable_recv,
        .output_recv = output_recv,
        .snapshot = snapshot,
        .restoring = false,
        .last_ack_send_ns = now,
        .ack_dirty = false,
        .output_cb = cb,
        .state_cb = state_cb,
        .end_cb = end_cb,
        .ctx = ctx,
        .last_state = .connected,
        .session_ended = false,
    };

    // Send Init immediately; zmosh_poll retransmits it if this datagram is
    // lost or the socket is temporarily blocked.
    flushReliable(session, now) catch {};

    set_status(status, .ok);
    return session;
}

export fn zmosh_get_fd(session: ?*const Session) c_int {
    const s = session orelse return -1;
    return s.udp_sock.getFd();
}

export fn zmosh_poll(session: ?*Session) Status {
    const s = session orelse return .err_null;
    if (s.session_ended) return .ok;

    const now: i64 = @intCast(std.time.nanoTimestamp());

    const reorder_timeout_ns = std.math.clamp(
        2 * (s.peer.srtt_us orelse 25_000),
        @as(i64, 50_000),
        @as(i64, 250_000),
    ) * std.time.ns_per_us;
    if (!s.restoring and s.output_recv.gapExpired(now, reorder_timeout_ns)) {
        return .err_output_stream_lost;
    }

    flushReliable(s, now) catch return .err_send;

    // Heartbeat + delayed ACKs.
    if (s.ack_dirty and (now - s.last_ack_send_ns) >= ack_delay_ns) {
        sendHeartbeat(s, now) catch {};
    } else if (s.peer.shouldSendHeartbeat(now, s.config)) {
        sendHeartbeat(s, now) catch {};
    }

    // State check
    const state = s.peer.updateState(now, s.config);
    const mapped: State = switch (state) {
        .connected => .connected,
        .disconnected => .disconnected,
        .dead => .dead,
    };
    if (state != s.last_state) {
        s.last_state = state;
        if (s.state_cb) |cb| cb(s.ctx, mapped);
    }
    if (state == .dead) return .err_dead;

    // Recv loop — drain all pending datagrams
    while (true) {
        var decrypt_buf: [9000]u8 = undefined;
        const recv_result = s.peer.recv(&s.udp_sock, &decrypt_buf) catch |err| {
            if (err == error.WouldBlock) break;
            return .err_poll;
        };
        const result = recv_result orelse break;

        const packet = transport.parsePacket(result.data) catch continue;
        s.reliable_send.ack(packet.ack, packet.ack_bits);

        switch (packet.channel) {
            .heartbeat => {},
            .reliable_ipc, .control, .snapshot => {
                s.ack_dirty = true;
                _ = s.reliable_recv.push(packet) catch return .err_poll;
                while (s.reliable_recv.popReady()) |ready| {
                    handleReliablePayload(s, ready.channel, ready.payload) catch |err| {
                        ready.deinit();
                        return if (err == error.OutputStreamLost) .err_output_stream_lost else .err_poll;
                    };
                    ready.deinit();
                }
                if (s.session_ended) return .ok;
            },
            .output => {
                if (s.restoring) continue;
                switch (s.output_recv.onPacket(packet.seq, packet.payload, now) catch return .err_poll) {
                    .accept => {
                        var made_progress = false;
                        while (s.output_recv.popReady()) |output| {
                            if (output.len > 0) {
                                s.output_cb(s.ctx, output.ptr, @intCast(output.len));
                            }
                            alloc.free(output);
                            made_progress = true;
                        }
                        s.output_recv.noteDrain(made_progress, now);
                    },
                    .gap => return .err_output_stream_lost,
                    .duplicate, .stale => {},
                }
            },
        }
    }

    flushReliable(s, now) catch return .err_send;
    return .ok;
}

export fn zmosh_send_input(session: ?*Session, data: ?[*]const u8, len: u32) Status {
    const s = session orelse return .err_null;
    const d = data orelse return .err_null;
    if (len == 0) return .ok;
    if (len > max_input_len) return .err_too_large;

    const payload = d[0..len];
    var off: usize = 0;
    while (off < payload.len) {
        const end = @min(off + max_ipc_payload, payload.len);
        sendIpcReliable(s, .Input, payload[off..end]) catch return .err_send;
        off = end;
    }
    const now: i64 = @intCast(std.time.nanoTimestamp());
    flushReliable(s, now) catch return .err_send;
    return .ok;
}

export fn zmosh_resize(session: ?*Session, rows: u16, cols: u16) Status {
    const s = session orelse return .err_null;

    const size = ipc.Resize{ .rows = rows, .cols = cols };
    sendIpcReliable(s, .Resize, std.mem.asBytes(&size)) catch return .err_send;
    const now: i64 = @intCast(std.time.nanoTimestamp());
    flushReliable(s, now) catch return .err_send;
    return .ok;
}

export fn zmosh_restore(session: ?*Session, rows: u16, cols: u16) Status {
    const s = session orelse return .err_null;

    beginRestore(s);
    const size = ipc.Resize{ .rows = rows, .cols = cols };
    sendIpcReliable(s, .Restore, std.mem.asBytes(&size)) catch return .err_send;
    const now: i64 = @intCast(std.time.nanoTimestamp());
    flushReliable(s, now) catch return .err_send;
    return .ok;
}

export fn zmosh_disconnect(session: ?*Session) void {
    const s = session orelse return;

    const now: i64 = @intCast(std.time.nanoTimestamp());
    sendIpcReliable(s, .Detach, "") catch {};
    flushReliable(s, now) catch {};

    s.snapshot.deinit();
    s.output_recv.deinit();
    s.reliable_recv.deinit();
    s.reliable_send.deinit();
    s.udp_sock.close();
    alloc.destroy(s);
}
