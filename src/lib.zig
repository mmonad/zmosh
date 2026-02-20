const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp_mod = @import("udp.zig");
const ipc = @import("ipc.zig");

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

    output_cb: OutputFn,
    state_cb: ?StateFn,
    end_cb: ?SessionEndFn,
    ctx: ?*anyopaque,

    last_state: udp_mod.PeerState,
    session_ended: bool,
};

// ---------------------------------------------------------------------------
// Helpers (mirrors remote.zig:buildIpcBytes)
// ---------------------------------------------------------------------------

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

    // Send Init with terminal size
    const size = ipc.Resize{ .rows = rows, .cols = cols };
    var init_buf: [128]u8 = undefined;
    const init_ipc = buildIpcBytes(.Init, std.mem.asBytes(&size), &init_buf);
    peer.send(&udp_sock, init_ipc) catch {
        udp_sock.close();
        set_status(status, .err_send);
        return null;
    };

    // Allocate session
    const session = std.heap.page_allocator.create(Session) catch {
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    session.* = .{
        .udp_sock = udp_sock,
        .peer = peer,
        .config = .{},
        .output_cb = cb,
        .state_cb = state_cb,
        .end_cb = end_cb,
        .ctx = ctx,
        .last_state = .connected,
        .session_ended = false,
    };

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

    // Heartbeat
    if (s.peer.shouldSendHeartbeat(now, s.config)) {
        s.peer.send(&s.udp_sock, "") catch {};
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

        // Parse IPC messages from decrypted plaintext
        var offset: usize = 0;
        while (offset < result.data.len) {
            const remaining = result.data[offset..];
            const msg_len = ipc.expectedLength(remaining) orelse break;
            if (remaining.len < msg_len) break;

            const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
            const payload = remaining[@sizeOf(ipc.Header)..msg_len];

            if (hdr.tag == .Output and payload.len > 0) {
                s.output_cb(s.ctx, payload.ptr, @intCast(payload.len));
            } else if (hdr.tag == .SessionEnd) {
                s.session_ended = true;
                if (s.end_cb) |cb| cb(s.ctx);
                return .ok;
            }
            offset += msg_len;
        }
    }

    return .ok;
}

/// Max input size per call — fits within a single UDP datagram after
/// IPC framing (5 bytes) and crypto overhead (24 bytes).
const max_input_len = 8192;

export fn zmosh_send_input(session: ?*Session, data: ?[*]const u8, len: u32) Status {
    const s = session orelse return .err_null;
    const d = data orelse return .err_null;
    if (len == 0) return .ok;
    if (len > max_input_len) return .err_too_large;

    var ipc_buf: [max_input_len + @sizeOf(ipc.Header)]u8 = undefined;
    const payload = d[0..len];
    const ipc_bytes = buildIpcBytes(.Input, payload, &ipc_buf);
    s.peer.send(&s.udp_sock, ipc_bytes) catch return .err_send;
    return .ok;
}

export fn zmosh_resize(session: ?*Session, rows: u16, cols: u16) Status {
    const s = session orelse return .err_null;

    const size = ipc.Resize{ .rows = rows, .cols = cols };
    var buf: [128]u8 = undefined;
    const ipc_bytes = buildIpcBytes(.Resize, std.mem.asBytes(&size), &buf);
    s.peer.send(&s.udp_sock, ipc_bytes) catch return .err_send;
    return .ok;
}

export fn zmosh_disconnect(session: ?*Session) void {
    const s = session orelse return;

    // Best-effort detach
    var detach_buf: [128]u8 = undefined;
    const detach_ipc = buildIpcBytes(.Detach, "", &detach_buf);
    s.peer.send(&s.udp_sock, detach_ipc) catch {};

    s.udp_sock.close();
    std.heap.page_allocator.destroy(s);
}
