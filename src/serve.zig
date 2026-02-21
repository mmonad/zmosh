const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");

const log = std.log.scoped(.serve);

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
    config: udp.Config,
    running: bool,

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
            const line = std.fmt.bufPrint(&out_buf, "ZMX_CONNECT udp {d} {s}\n", .{ udp_sock.bound_port, encoded_key }) catch unreachable;
            _ = try posix.write(posix.STDOUT_FILENO, line);
        }

        // Close stdout so SSH session can terminate
        posix.close(posix.STDOUT_FILENO);

        // Initialize peer (we send to_client, recv to_server from remote client)
        const peer = udp.Peer.init(key, .to_client);

        const unix_read_buf = try ipc.SocketBuffer.init(alloc);
        const unix_write_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);

        log.info("gateway started session={s} udp_port={d}", .{ session_name, udp_sock.bound_port });

        return .{
            .alloc = alloc,
            .udp_sock = udp_sock,
            .unix_fd = unix_fd,
            .peer = peer,
            .unix_read_buf = unix_read_buf,
            .unix_write_buf = unix_write_buf,
            .config = config,
            .running = true,
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

            // Send heartbeat if needed
            if (self.peer.addr != null and self.peer.shouldSendHeartbeat(now, self.config)) {
                self.peer.send(&self.udp_sock, "") catch |err| {
                    log.debug("heartbeat send failed: {s}", .{@errorName(err)});
                };
            }

            // Check peer state
            const state = self.peer.updateState(now, self.config);
            if (state == .dead) {
                log.info("peer dead (alive timeout), shutting down", .{});
                break;
            }

            // Build poll fds
            var poll_fds: [3]posix.pollfd = undefined;
            poll_fds[0] = .{ .fd = self.udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };

            var unix_events: i16 = posix.POLL.IN;
            if (self.unix_write_buf.items.len > 0) {
                unix_events |= posix.POLL.OUT;
            }
            poll_fds[1] = .{ .fd = self.unix_fd, .events = unix_events, .revents = 0 };

            // Use heartbeat interval as poll timeout so we send heartbeats on time
            const poll_timeout: i32 = @intCast(@min(self.config.heartbeat_interval_ms, 1000));
            _ = posix.poll(poll_fds[0..2], poll_timeout) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };

            // Handle incoming UDP datagrams → decrypt → forward to Unix socket
            if (poll_fds[0].revents & posix.POLL.IN != 0) {
                var decrypt_buf: [9000]u8 = undefined;
                if (try self.peer.recv(&self.udp_sock, &decrypt_buf)) |result| {
                    if (result.data.len > 0) {
                        // Plaintext is raw IPC bytes — forward directly to daemon
                        try self.unix_write_buf.appendSlice(self.alloc, result.data);
                    }
                }
            }

            // Handle Unix socket read → encrypt → send as UDP datagram
            if (poll_fds[1].revents & posix.POLL.IN != 0) {
                const n = self.unix_read_buf.read(self.unix_fd) catch |err| {
                    if (err == error.WouldBlock) {} else {
                        log.warn("unix read error: {s}", .{@errorName(err)});
                        break;
                    }
                    continue;
                };
                if (n == 0) {
                    log.info("daemon closed connection", .{});
                    break;
                }

                // Forward each complete IPC message as encrypted UDP datagrams.
                // Large Output messages are chunked to stay under the network MTU
                // and avoid IP fragmentation (which causes silent packet loss).
                while (self.unix_read_buf.next()) |msg| {
                    self.forwardToUdp(msg.header.tag, msg.payload);
                }
            }

            // Flush buffered writes to Unix socket
            if (poll_fds[1].revents & posix.POLL.OUT != 0) {
                if (self.unix_write_buf.items.len > 0) {
                    const written = posix.write(self.unix_fd, self.unix_write_buf.items) catch |err| blk: {
                        if (err == error.WouldBlock) break :blk 0;
                        log.warn("unix write error: {s}", .{@errorName(err)});
                        break;
                    };
                    if (written > 0) {
                        self.unix_write_buf.replaceRange(self.alloc, 0, written, &[_]u8{}) catch unreachable;
                    }
                }
            }

            // Handle Unix socket errors
            if (poll_fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                log.info("unix socket closed/error", .{});
                break;
            }
        }

        // Notify client that the session has ended
        if (self.peer.addr != null) {
            const header = ipc.Header{ .tag = .SessionEnd, .len = 0 };
            self.peer.send(&self.udp_sock, std.mem.asBytes(&header)) catch |err| {
                log.debug("failed to send SessionEnd: {s}", .{@errorName(err)});
            };
        }
    }

    // Max IPC payload per UDP datagram to avoid IP fragmentation.
    // 1472 (Ethernet MTU minus IP+UDP headers) - 24 (crypto) - 5 (IPC header) = 1443.
    // Use 1200 to leave headroom for tunnels/VPNs.
    const max_chunk = 1200 - crypto.overhead - @sizeOf(ipc.Header);

    fn forwardToUdp(self: *Gateway, tag: ipc.Tag, payload: []const u8) void {
        if (tag == .Output and payload.len > max_chunk) {
            // Split large Output into MTU-safe chunks
            var off: usize = 0;
            while (off < payload.len) {
                const end = @min(off + max_chunk, payload.len);
                self.sendIpcDatagram(.Output, payload[off..end]);
                off = end;
            }
        } else {
            self.sendIpcDatagram(tag, payload);
        }
    }

    fn sendIpcDatagram(self: *Gateway, tag: ipc.Tag, payload: []const u8) void {
        var buf: [1200]u8 = undefined;
        const hdr = ipc.Header{ .tag = tag, .len = @intCast(payload.len) };
        @memcpy(buf[0..@sizeOf(ipc.Header)], std.mem.asBytes(&hdr));
        if (payload.len > 0) {
            @memcpy(buf[@sizeOf(ipc.Header)..][0..payload.len], payload);
        }
        self.peer.send(&self.udp_sock, buf[0 .. @sizeOf(ipc.Header) + payload.len]) catch |err| {
            if (err == error.NoPeerAddress) {
                log.debug("no peer address, dropping IPC tag={d}", .{@intFromEnum(tag)});
            } else if (err == error.WouldBlock) {
                log.debug("udp send would block", .{});
            } else {
                log.warn("udp send error: {s}", .{@errorName(err)});
            }
        };
    }

    pub fn deinit(self: *Gateway) void {
        posix.close(self.unix_fd);
        self.udp_sock.close();
        self.unix_read_buf.deinit();
        self.unix_write_buf.deinit(self.alloc);
    }
};

/// Entry point for `zmx serve <session>`.
pub fn serveMain(alloc: std.mem.Allocator, session_name: []const u8) !void {
    return serveMainWithTransport(alloc, session_name, .udp);
}

pub fn serveMainWithTransport(
    alloc: std.mem.Allocator,
    session_name: []const u8,
    kind: transport.Kind,
) !void {
    if (kind != .udp) {
        log.err("QUIC transport is experimental and not implemented yet", .{});
        return error.TransportNotImplemented;
    }

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
    const line = try std.fmt.bufPrint(&buf, "ZMX_CONNECT udp {d} {s}\n", .{ port, encoded });

    // Verify it starts with the expected prefix
    try std.testing.expect(std.mem.startsWith(u8, line, "ZMX_CONNECT udp "));

    // Parse back
    var it = std.mem.splitScalar(u8, std.mem.trimRight(u8, line, "\n"), ' ');
    try std.testing.expectEqualStrings("ZMX_CONNECT", it.next().?);
    try std.testing.expectEqualStrings("udp", it.next().?);
    const port_str = it.next().?;
    const parsed_port = try std.fmt.parseInt(u16, port_str, 10);
    try std.testing.expect(parsed_port == 60042);
    const key_str = it.next().?;
    const decoded_key = try crypto.keyFromBase64(key_str);
    try std.testing.expectEqual(key, decoded_key);
}

test "IPC message round-trip through gateway encoding" {
    // Simulate what the gateway does: wrap IPC bytes, encrypt, decrypt, unwrap
    const key = crypto.generateKey();
    const payload = "hello world";

    // Build IPC message bytes (as the gateway would receive from daemon)
    const header = ipc.Header{ .tag = .Output, .len = @intCast(payload.len) };
    const header_bytes = std.mem.asBytes(&header);
    var ipc_msg: [@sizeOf(ipc.Header) + payload.len]u8 = undefined;
    @memcpy(ipc_msg[0..@sizeOf(ipc.Header)], header_bytes);
    @memcpy(ipc_msg[@sizeOf(ipc.Header)..], payload);

    // Encrypt (as gateway sends to remote client)
    var enc_buf: [crypto.overhead + ipc_msg.len]u8 = undefined;
    const datagram = try crypto.encodeDatagram(key, .to_client, 0, &ipc_msg, &enc_buf);

    // Decrypt (as remote client receives)
    var dec_buf: [ipc_msg.len]u8 = undefined;
    const decoded = try crypto.decodeDatagram(key, .to_client, datagram, &dec_buf);

    // Verify the IPC message is intact
    try std.testing.expect(decoded.plaintext.len == ipc_msg.len);
    const dec_header = std.mem.bytesToValue(ipc.Header, decoded.plaintext[0..@sizeOf(ipc.Header)]);
    try std.testing.expect(dec_header.tag == .Output);
    try std.testing.expect(dec_header.len == payload.len);
    try std.testing.expectEqualStrings(payload, decoded.plaintext[@sizeOf(ipc.Header)..]);
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
