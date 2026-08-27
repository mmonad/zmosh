const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");

const log = std.log.scoped(.serve);

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_unix_write_buf = 1024 * 1024;
const max_reliable_backlog = 4 * 1024 * 1024;
const ack_delay_ns = 20 * std.time.ns_per_ms;

var sigterm_received: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn handleSigterm(_: i32, _: *const posix.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    sigterm_received.store(true, .release);
}

fn setupSigtermHandler() void {
    const act: posix.Sigaction = .{
        .handler = .{ .sigaction = handleSigterm },
        .mask = posix.sigemptyset(),
        .flags = posix.SA.SIGINFO,
    };
    posix.sigaction(posix.SIG.TERM, &act, null);
}

/// Resolve the zmx socket directory, following the same logic as main.zig's Cfg.init.
fn resolveSocketDir(alloc: std.mem.Allocator) ![]const u8 {
    if (posix.getenv("ZMX_DIR")) |zmxdir|
        return try alloc.dupe(u8, zmxdir);
    const tmpdir = std.mem.trimRight(u8, posix.getenv("TMPDIR") orelse "/tmp", "/");
    const uid = posix.getuid();
    if (posix.getenv("XDG_RUNTIME_DIR")) |xdg_runtime|
        return try std.fmt.allocPrint(alloc, "{s}/zmx", .{xdg_runtime});
    return try std.fmt.allocPrint(alloc, "{s}/zmx-{d}", .{ tmpdir, uid });
}

/// Connect to the daemon's Unix socket (same as sessionConnect in main.zig).
fn connectUnix(path: []const u8) !i32 {
    var unix_addr = try std.net.Address.initUnix(path);
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    try posix.connect(fd, &unix_addr.any, unix_addr.getOsSockLen());
    // Make non-blocking for poll loop
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.SOCK.NONBLOCK);
    return fd;
}

pub const Gateway = struct {
    alloc: std.mem.Allocator,
    udp_sock: udp.UdpSocket,
    unix_fd: i32,
    peer: udp.Peer,
    unix_read_buf: ipc.SocketBuffer,
    unix_write_buf: std.ArrayList(u8),

    reliable_send: transport.ReliableSend,
    reliable_recv: transport.OrderedRecv,

    awaiting_restore: bool,
    snapshot_active: bool,
    snapshot_generation: u32,
    snapshot_seq_range: transport.SnapshotSeqRange,

    config: udp.Config,
    running: bool,

    last_ack_send_ns: i64,
    ack_dirty: bool,

    pub fn init(
        alloc: std.mem.Allocator,
        session_name: []const u8,
        config: udp.Config,
    ) !Gateway {
        const socket_dir = try resolveSocketDir(alloc);
        defer alloc.free(socket_dir);

        const socket_path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ socket_dir, session_name });
        defer alloc.free(socket_path);

        // Connect to the daemon's Unix socket
        const unix_fd = connectUnix(socket_path) catch |err| {
            log.err("failed to connect to daemon socket={s} err={s}", .{ socket_path, @errorName(err) });
            return err;
        };
        errdefer posix.close(unix_fd);

        // Bind a UDP socket in the configured port range
        var udp_sock = try udp.UdpSocket.bind(config.port_range_start, config.port_range_end);
        errdefer udp_sock.close();

        // Generate session key
        const key = crypto.generateKey();
        const encoded_key = crypto.keyToBase64(key);

        // Print bootstrap line for SSH capture
        {
            var out_buf: [256]u8 = undefined;
            const line = std.fmt.bufPrint(&out_buf, "ZMX_CONNECT udp-v2 {d} {s}\n", .{ udp_sock.bound_port, encoded_key }) catch unreachable;
            _ = try posix.write(posix.STDOUT_FILENO, line);
        }

        // Close stdout so SSH session can terminate
        posix.close(posix.STDOUT_FILENO);

        // Initialize peer (we send to_client, recv to_server from remote client)
        const peer = udp.Peer.init(key, .to_client);

        const unix_read_buf = try ipc.SocketBuffer.init(alloc);
        const unix_write_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
        const reliable_send = try transport.ReliableSend.init(alloc);
        var reliable_recv = try transport.OrderedRecv.init(alloc);
        errdefer reliable_recv.deinit();

        const now: i64 = @intCast(std.time.nanoTimestamp());

        log.info("gateway started session={s} udp_port={d}", .{ session_name, udp_sock.bound_port });

        return .{
            .alloc = alloc,
            .udp_sock = udp_sock,
            .unix_fd = unix_fd,
            .peer = peer,
            .unix_read_buf = unix_read_buf,
            .unix_write_buf = unix_write_buf,
            .reliable_send = reliable_send,
            .reliable_recv = reliable_recv,
            .awaiting_restore = false,
            .snapshot_active = false,
            .snapshot_generation = 0,
            .snapshot_seq_range = .{ .first = 0, .last = 0 },
            .config = config,
            .running = true,
            .last_ack_send_ns = now,
            .ack_dirty = false,
        };
    }

    pub fn run(self: *Gateway) !void {
        setupSigtermHandler();

        while (self.running) {
            if (sigterm_received.swap(false, .acq_rel)) {
                log.info("SIGTERM received, shutting down gateway", .{});
                break;
            }

            const now: i64 = @intCast(std.time.nanoTimestamp());

            // Check peer state
            const state = self.peer.updateState(now, self.config);
            if (state == .dead) {
                log.info("peer dead (alive timeout), shutting down", .{});
                break;
            }

            try self.flushReliable(now);
            self.updateSnapshotState();

            if (self.peer.addr != null) {
                if (self.ack_dirty and (now - self.last_ack_send_ns >= ack_delay_ns)) {
                    self.sendHeartbeat(now) catch |err| {
                        if (err != error.NoPeerAddress and err != error.WouldBlock) return err;
                    };
                } else if (self.peer.shouldSendHeartbeat(now, self.config)) {
                    self.sendHeartbeat(now) catch |err| {
                        if (err != error.NoPeerAddress and err != error.WouldBlock) return err;
                    };
                }
            }

            // Build poll fds
            var poll_fds: [2]posix.pollfd = undefined;
            poll_fds[0] = .{ .fd = self.udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };

            // Reliable terminal output is intentionally backpressured. Once
            // the network queue reaches the cap, let the Unix socket apply
            // normal stream backpressure until acknowledgements drain it.
            var unix_events: i16 = if (self.reliable_send.pendingBytes() < max_reliable_backlog)
                posix.POLL.IN
            else
                0;
            if (self.unix_write_buf.items.len > 0) {
                unix_events |= posix.POLL.OUT;
            }
            poll_fds[1] = .{ .fd = self.unix_fd, .events = unix_events, .revents = 0 };

            const poll_timeout = self.computePollTimeoutMs();
            _ = posix.poll(&poll_fds, poll_timeout) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };
            const polled_unix_fd = poll_fds[1].fd;

            // Handle incoming UDP datagrams → decrypt → decode transport packet
            if (poll_fds[0].revents & posix.POLL.IN != 0) {
                while (true) {
                    var decrypt_buf: [9000]u8 = undefined;
                    const recv_result = try self.peer.recv(&self.udp_sock, &decrypt_buf);
                    const result = recv_result orelse break;
                    try self.handleTransportPacket(result.data);
                }
            }

            // Handle Unix socket read → forward to UDP transport
            if (polled_unix_fd == self.unix_fd and poll_fds[1].revents & posix.POLL.IN != 0) {
                while (true) {
                    const n = self.unix_read_buf.read(self.unix_fd) catch |err| {
                        if (err == error.WouldBlock) break;
                        log.warn("unix read error: {s}", .{@errorName(err)});
                        self.running = false;
                        break;
                    };
                    if (!self.running) break;
                    if (n == 0) {
                        log.info("daemon closed connection", .{});
                        self.running = false;
                        break;
                    }

                    while (self.unix_read_buf.next()) |msg| {
                        try self.forwardDaemonMessage(msg.header.tag, msg.payload);
                    }
                }
            }

            // Flush buffered writes to Unix socket
            if (polled_unix_fd == self.unix_fd and poll_fds[1].revents & posix.POLL.OUT != 0) {
                if (self.unix_write_buf.items.len > 0) {
                    const written = posix.write(self.unix_fd, self.unix_write_buf.items) catch |err| blk: {
                        if (err == error.WouldBlock) break :blk @as(usize, 0);
                        log.warn("unix write error: {s}", .{@errorName(err)});
                        self.running = false;
                        break :blk @as(usize, 0);
                    };
                    if (written > 0) {
                        self.unix_write_buf.replaceRange(self.alloc, 0, written, &[_]u8{}) catch unreachable;
                    }
                }
            }

            if (polled_unix_fd == self.unix_fd and poll_fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                log.info("unix socket closed/error", .{});
                break;
            }
        }

        // Notify client that the session has ended.
        if (self.peer.addr != null) {
            const now: i64 = @intCast(std.time.nanoTimestamp());
            self.sendIpcReliable(.SessionEnd, "") catch |err| {
                log.debug("failed to send SessionEnd: {s}", .{@errorName(err)});
            };
            self.flushReliable(now) catch {};
        }
    }

    fn computePollTimeoutMs(self: *const Gateway) i32 {
        var timeout: i64 = @min(@as(i64, self.config.heartbeat_interval_ms), 1000);

        if (self.reliable_send.hasPending()) {
            const rto_ms = @divFloor(self.peer.rto_us(), 1000);
            timeout = @min(timeout, @max(@as(i64, 1), rto_ms));
        }

        if (self.ack_dirty) timeout = @min(timeout, @as(i64, 20));

        return @intCast(@max(@as(i64, 0), timeout));
    }

    fn sendHeartbeat(self: *Gateway, now: i64) !void {
        var pkt_buf: [1200]u8 = undefined;
        const pkt = try transport.buildUnreliable(
            .heartbeat,
            0,
            self.reliable_recv.ack(),
            self.reliable_recv.ackBits(),
            "",
            &pkt_buf,
        );
        try self.peer.send(&self.udp_sock, pkt);
        self.last_ack_send_ns = now;
        self.ack_dirty = false;
    }

    fn flushReliable(self: *Gateway, now: i64) !void {
        var packets = try self.reliable_send.collectTransmissions(self.alloc, now, self.peer.rto_us());
        defer packets.deinit(self.alloc);

        for (packets.items) |packet| {
            self.peer.send(&self.udp_sock, packet) catch |err| {
                if (err == error.NoPeerAddress or err == error.WouldBlock) continue;
                return err;
            };
        }
    }

    fn trackClientMessages(self: *Gateway, payload: []const u8) void {
        var offset: usize = 0;
        while (offset < payload.len) {
            const remaining = payload[offset..];
            const msg_len = ipc.expectedLength(remaining) orelse break;
            if (remaining.len < msg_len) break;

            const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
            if (hdr.tag == .Restore and !self.snapshot_active) {
                self.awaiting_restore = true;
            }

            offset += msg_len;
        }
    }

    fn appendUnixWrite(self: *Gateway, payload: []const u8) !void {
        if (self.unix_write_buf.items.len + payload.len > max_unix_write_buf) {
            return error.UnixWriteBackpressure;
        }
        try self.unix_write_buf.appendSlice(self.alloc, payload);
    }

    fn queueSnapshot(self: *Gateway, payload: []const u8) !void {
        self.snapshot_generation +%= 1;
        if (self.snapshot_generation == 0) self.snapshot_generation = 1;

        self.snapshot_seq_range = try transport.queueSnapshot(
            &self.reliable_send,
            self.snapshot_generation,
            payload,
            1,
            self.reliable_recv.ack(),
            self.reliable_recv.ackBits(),
        );
        self.awaiting_restore = false;
        self.snapshot_active = true;
        log.info("queued terminal snapshot generation={d} bytes={d} reliable_seq={d}..{d}", .{
            self.snapshot_generation,
            payload.len,
            self.snapshot_seq_range.first,
            self.snapshot_seq_range.last,
        });
    }

    fn updateSnapshotState(self: *Gateway) void {
        if (!self.snapshot_active) return;
        if (self.reliable_send.hasPendingRange(self.snapshot_seq_range.first, self.snapshot_seq_range.last)) return;

        self.snapshot_active = false;
        log.info("terminal snapshot acknowledged generation={d}", .{self.snapshot_generation});
    }

    fn handleTransportPacket(self: *Gateway, plaintext: []const u8) !void {
        const packet = transport.parsePacket(plaintext) catch |err| {
            log.debug("transport parse failed: {s}", .{@errorName(err)});
            return;
        };

        self.reliable_send.ack(packet.ack, packet.ack_bits);

        switch (packet.channel) {
            .heartbeat => {},
            .output => {
                // Client never sends output channel packets.
            },
            .reliable_ipc, .control, .snapshot => {
                self.ack_dirty = true;
                const action = try self.reliable_recv.push(packet);
                if (action == .stale) {
                    log.warn("reliable packet outside receive window seq={d}", .{packet.seq});
                }

                while (self.reliable_recv.popReady()) |ready| {
                    defer ready.deinit();
                    try self.handleReliablePacket(ready.channel, ready.payload);
                }
            },
        }
    }

    fn handleReliablePacket(self: *Gateway, channel: transport.Channel, payload: []const u8) !void {
        switch (channel) {
            .reliable_ipc => {
                self.trackClientMessages(payload);
                self.appendUnixWrite(payload) catch |err| {
                    log.warn("unix write buffer overflow: {s}", .{@errorName(err)});
                    self.running = false;
                };
            },
            .control => {
                const ctrl = transport.parseControl(payload) catch return;
                if (ctrl == .resync_request) {
                    // Repainting an attached terminal is never automatic. A
                    // client that needs state reconnects with --restore.
                    log.warn("ignored automatic terminal snapshot request", .{});
                }
            },
            .heartbeat, .output, .snapshot => {},
        }
    }

    fn sendReliablePayload(self: *Gateway, channel: transport.Channel, payload: []const u8) !void {
        _ = try self.reliable_send.queue(
            channel,
            payload,
            self.reliable_recv.ack(),
            self.reliable_recv.ackBits(),
        );
    }

    fn sendIpcReliable(self: *Gateway, tag: ipc.Tag, payload: []const u8) !void {
        if (payload.len <= max_ipc_payload) {
            var buf: [transport.max_payload_len]u8 = undefined;
            const ipc_bytes = transport.buildIpcBytes(tag, payload, &buf);
            try self.sendReliablePayload(.reliable_ipc, ipc_bytes);
            return;
        }

        var off: usize = 0;
        while (off < payload.len) {
            const end = @min(off + max_ipc_payload, payload.len);
            var buf: [transport.max_payload_len]u8 = undefined;
            const ipc_bytes = transport.buildIpcBytes(tag, payload[off..end], &buf);
            try self.sendReliablePayload(.reliable_ipc, ipc_bytes);
            off = end;
        }
    }

    fn forwardDaemonMessage(self: *Gateway, tag: ipc.Tag, payload: []const u8) !void {
        if (tag == .Output) {
            if (self.awaiting_restore) {
                try self.queueSnapshot(payload);
                return;
            }
            // Terminal bytes are a stateful stream: losing one cursor escape
            // corrupts every following update. Put Output on the same ordered,
            // retransmitted channel as the rest of IPC.
            try self.sendIpcReliable(.Output, payload);
            return;
        }

        try self.sendIpcReliable(tag, payload);
    }

    pub fn deinit(self: *Gateway) void {
        posix.close(self.unix_fd);
        self.udp_sock.close();
        self.unix_read_buf.deinit();
        self.unix_write_buf.deinit(self.alloc);
        self.reliable_send.deinit();
        self.reliable_recv.deinit();
    }
};

/// Entry point for `zmx serve <session>`.
pub fn serveMain(alloc: std.mem.Allocator, session_name: []const u8) !void {
    var gw = try Gateway.init(alloc, session_name, .{});
    defer gw.deinit();
    try gw.run();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "bootstrap output format" {
    const key = crypto.generateKey();
    const encoded = crypto.keyToBase64(key);
    const port: u16 = 60042;

    var buf: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "ZMX_CONNECT udp-v2 {d} {s}\n", .{ port, encoded });

    // Verify it starts with the expected prefix
    try std.testing.expect(std.mem.startsWith(u8, line, "ZMX_CONNECT udp-v2 "));

    // Parse back
    var it = std.mem.splitScalar(u8, std.mem.trimRight(u8, line, "\n"), ' ');
    try std.testing.expectEqualStrings("ZMX_CONNECT", it.next().?);
    try std.testing.expectEqualStrings("udp-v2", it.next().?);
    const port_str = it.next().?;
    const parsed_port = try std.fmt.parseInt(u16, port_str, 10);
    try std.testing.expect(parsed_port == 60042);
    const key_str = it.next().?;
    const decoded_key = try crypto.keyFromBase64(key_str);
    try std.testing.expectEqual(key, decoded_key);
}

test "resolveSocketDir returns valid path" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const dir = try resolveSocketDir(alloc);
    defer alloc.free(dir);
    try std.testing.expect(dir.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, dir, "zmx") != null);
}
