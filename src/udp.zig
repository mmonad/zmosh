const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");

const log = std.log.scoped(.udp);

/// Truncate nanoTimestamp (i128) to i64 for storage. Sufficient for ~292 years.
fn nanoNow() i64 {
    return @intCast(std.time.nanoTimestamp());
}

pub const Config = struct {
    heartbeat_interval_ms: u32 = 1000,
    heartbeat_timeout_ms: u32 = 5000,
    alive_timeout_ms: u32 = 86400 * 1000,
    port_range_start: u16 = 60000,
    port_range_end: u16 = 61000,
};

pub const PeerState = enum {
    connected,
    disconnected,
    dead,
};

pub const UdpSocket = struct {
    fd: i32,
    bound_port: u16,

    /// Bind a non-blocking UDP socket to the first available port in [port_start, port_end).
    /// Uses AF.INET6 with dual-stack when possible, falling back to AF.INET.
    pub fn bind(port_start: u16, port_end: u16) !UdpSocket {
        if (bindFamily(posix.AF.INET6, port_start, port_end, true)) |sock| return sock;
        if (bindFamily(posix.AF.INET, port_start, port_end, false)) |sock| return sock;
        return error.AddressInUse;
    }

    fn bindFamily(family: u32, port_start: u16, port_end: u16, set_v6only: bool) ?UdpSocket {
        const fd = posix.socket(
            family,
            posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
            0,
        ) catch return null;

        if (set_v6only) {
            const v6only: i32 = 0;
            posix.setsockopt(fd, posix.IPPROTO.IPV6, std.os.linux.IPV6.V6ONLY, std.mem.asBytes(&v6only)) catch {
                posix.close(fd);
                return null;
            };
        }

        var port = port_start;
        while (port < port_end) : (port += 1) {
            const addr = if (family == posix.AF.INET6)
                std.net.Address.initIp6(.{0} ** 16, port, 0, 0)
            else
                std.net.Address.initIp4(.{0} ** 4, port);
            posix.bind(fd, &addr.any, addr.getOsSockLen()) catch continue;
            log.info("bound udp port={d} family={s}", .{
                port,
                if (family == posix.AF.INET6) "inet6" else "inet",
            });
            return .{ .fd = fd, .bound_port = port };
        }

        posix.close(fd);
        return null;
    }

    pub fn getFd(self: *const UdpSocket) i32 {
        return self.fd;
    }

    pub fn sendTo(self: *UdpSocket, data: []const u8, addr: std.net.Address) !void {
        _ = posix.sendto(self.fd, data, 0, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock => return error.WouldBlock,
            else => return err,
        };
    }

    pub fn recvFrom(self: *UdpSocket, buf: []u8) !struct { len: usize, addr: std.net.Address } {
        var src_addr: posix.sockaddr.storage = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        const n = posix.recvfrom(self.fd, buf, 0, @ptrCast(&src_addr), &addr_len) catch |err| switch (err) {
            error.WouldBlock => return error.WouldBlock,
            else => return err,
        };
        // Copy the full address returned by the kernel — not just the first
        // sizeof(sockaddr) bytes — so IPv6 addresses (28 bytes) aren't truncated.
        var addr: std.net.Address = std.mem.zeroes(std.net.Address);
        const len = @min(@as(usize, @intCast(addr_len)), @sizeOf(std.net.Address));
        @memcpy(
            std.mem.asBytes(&addr)[0..len],
            std.mem.asBytes(&src_addr)[0..len],
        );
        return .{
            .len = n,
            .addr = addr,
        };
    }

    pub fn close(self: *UdpSocket) void {
        posix.close(self.fd);
    }
};

pub const Peer = struct {
    addr: ?std.net.Address,
    key: crypto.Key,

    // Sequence numbers
    send_seq: u63,
    max_recv_seq: u63,

    // RTT estimation (RFC 6298, 50ms min RTO like Mosh)
    srtt_us: ?i64,
    rttvar_us: ?i64,

    // Timestamps for RTT measurement
    last_send_time: ?i64,

    // Heartbeat tracking
    last_recv_time: i64,
    last_send_time_any: i64,

    // State
    state: PeerState,
    direction: crypto.Direction,

    pub fn init(key: crypto.Key, direction: crypto.Direction) Peer {
        const now = nanoNow();
        return .{
            .addr = null,
            .key = key,
            .send_seq = 0,
            .max_recv_seq = 0,
            .srtt_us = null,
            .rttvar_us = null,
            .last_send_time = null,
            .last_recv_time = now,
            .last_send_time_any = now,
            .state = .connected,
            .direction = direction,
        };
    }

    /// Send an encrypted datagram. Increments send_seq.
    pub fn send(self: *Peer, sock: *UdpSocket, plaintext: []const u8) !void {
        const addr = self.addr orelse return error.NoPeerAddress;

        var buf: [9000]u8 = undefined;
        const datagram = try crypto.encodeDatagram(
            self.key,
            self.direction,
            self.send_seq,
            plaintext,
            &buf,
        );

        try sock.sendTo(datagram, addr);

        const now = nanoNow();
        self.last_send_time = now;
        self.last_send_time_any = now;
        self.send_seq += 1;
    }

    /// Try to receive and decrypt a datagram. Updates peer address on success (roaming).
    /// Returns null if no data available (EAGAIN) or decryption fails.
    pub fn recv(self: *Peer, sock: *UdpSocket, buf: []u8) !?struct { data: []u8, from: std.net.Address } {
        var raw: [9000]u8 = undefined;
        const result = sock.recvFrom(&raw) catch |err| switch (err) {
            error.WouldBlock => return null,
            else => return err,
        };

        // Determine expected direction: if we send to_server, we receive to_client
        const recv_direction: crypto.Direction = switch (self.direction) {
            .to_server => .to_client,
            .to_client => .to_server,
        };

        const decoded = crypto.decodeDatagram(
            self.key,
            recv_direction,
            raw[0..result.len],
            buf,
        ) catch |err| {
            log.debug("decrypt failed: {s}", .{@errorName(err)});
            return null;
        };

        const now = nanoNow();

        // Anti-replay + roaming: only update state if seq > max_recv_seq.
        // Old or duplicate packets are dropped after authentication.
        if (decoded.seq > self.max_recv_seq) {
            self.addr = result.addr;
            self.max_recv_seq = decoded.seq;
            self.last_recv_time = now;

            // RTT measurement
            if (self.last_send_time) |send_time| {
                const rtt_ns = now - send_time;
                if (rtt_ns > 0) {
                    self.updateRtt(@divFloor(rtt_ns, std.time.ns_per_us));
                }
                self.last_send_time = null;
            }
        } else if (decoded.seq == 0 and self.max_recv_seq == 0) {
            // First packet (seq 0)
            self.addr = result.addr;
            self.max_recv_seq = 0;
            self.last_recv_time = now;
        } else {
            log.debug("old seq={d} max={d}", .{ decoded.seq, self.max_recv_seq });
            return null;
        }

        if (self.state == .disconnected) {
            self.state = .connected;
            log.info("peer reconnected", .{});
        }

        return .{ .data = decoded.plaintext, .from = result.addr };
    }

    /// Check if a heartbeat should be sent.
    pub fn shouldSendHeartbeat(self: *const Peer, now: i64, config: Config) bool {
        const interval_ns = @as(i64, config.heartbeat_interval_ms) * std.time.ns_per_ms;
        return (now - self.last_send_time_any) >= interval_ns;
    }

    /// Update peer state based on time since last recv.
    pub fn updateState(self: *Peer, now: i64, config: Config) PeerState {
        const since_recv_ns = now - self.last_recv_time;
        const alive_ns = @as(i64, config.alive_timeout_ms) * std.time.ns_per_ms;
        const hb_ns = @as(i64, config.heartbeat_timeout_ms) * std.time.ns_per_ms;

        if (since_recv_ns >= alive_ns) {
            self.state = .dead;
        } else if (since_recv_ns >= hb_ns) {
            if (self.state == .connected) {
                log.warn("peer disconnected (heartbeat timeout)", .{});
            }
            self.state = .disconnected;
        }

        return self.state;
    }

    /// Compute the retransmission timeout in microseconds.
    pub fn rto_us(self: *const Peer) i64 {
        const min_rto: i64 = 50_000; // 50ms
        if (self.srtt_us) |srtt| {
            const rttvar = self.rttvar_us orelse 0;
            return @max(min_rto, srtt + 4 * rttvar);
        }
        return 1_000_000; // 1s default
    }

    /// Update RTT estimate (RFC 6298, 50ms min RTO).
    fn updateRtt(self: *Peer, rtt_us: i64) void {
        if (self.srtt_us) |srtt| {
            const rttvar = self.rttvar_us orelse 0;
            const diff = if (srtt > rtt_us) srtt - rtt_us else rtt_us - srtt;
            self.rttvar_us = @divFloor(3 * rttvar, 4) + @divFloor(diff, 4);
            self.srtt_us = @divFloor(7 * srtt, 8) + @divFloor(rtt_us, 8);
        } else {
            self.srtt_us = rtt_us;
            self.rttvar_us = @divFloor(rtt_us, 2);
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Bind a non-blocking IPv4-only UDP socket on loopback for testing.
fn testBindIp4(port_start: u16, port_end: u16) !UdpSocket {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    var port = port_start;
    while (port < port_end) : (port += 1) {
        const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
        posix.bind(fd, &addr.any, addr.getOsSockLen()) catch continue;
        return .{ .fd = fd, .bound_port = port };
    }
    posix.close(fd);
    return error.AddressInUse;
}

fn testPollReady(fd: i32) !void {
    var poll_fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    _ = try posix.poll(&poll_fds, 1000);
}

test "UdpSocket bind in port range" {
    var sock = try UdpSocket.bind(60900, 60910);
    defer sock.close();
    try std.testing.expect(sock.bound_port >= 60900);
    try std.testing.expect(sock.bound_port < 60910);
    try std.testing.expect(sock.fd >= 0);
}

test "UdpSocket bind fails on empty range" {
    const result = UdpSocket.bind(60000, 60000);
    try std.testing.expectError(error.AddressInUse, result);
}

test "Peer send/recv round-trip (loopback)" {
    const key = crypto.generateKey();
    var server_peer = Peer.init(key, .to_client);

    var server_sock = try testBindIp4(60910, 60920);
    defer server_sock.close();
    var client_sock = try testBindIp4(60920, 60930);
    defer client_sock.close();

    const msg = "hello, server!";
    var enc_buf: [crypto.overhead + msg.len]u8 = undefined;
    const datagram = try crypto.encodeDatagram(key, .to_server, 0, msg, &enc_buf);
    try client_sock.sendTo(datagram, std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server_sock.bound_port));

    try testPollReady(server_sock.fd);
    var peer_buf: [4096]u8 = undefined;
    const recv_result = try server_peer.recv(&server_sock, &peer_buf);
    try std.testing.expect(recv_result != null);
    try std.testing.expectEqualStrings(msg, recv_result.?.data);
}

test "Anti-replay: reject datagram with seq <= max_recv_seq" {
    const key = crypto.generateKey();
    var peer = Peer.init(key, .to_client);

    var sock_recv = try testBindIp4(60930, 60940);
    defer sock_recv.close();
    var sock_send = try testBindIp4(60940, 60950);
    defer sock_send.close();

    const target = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, sock_recv.bound_port);

    var buf_lo: [128]u8 = undefined;
    const pkt_lo = try crypto.encodeDatagram(key, .to_server, 5, "first", &buf_lo);
    var buf_hi: [128]u8 = undefined;
    const pkt_hi = try crypto.encodeDatagram(key, .to_server, 10, "second", &buf_hi);

    // Send higher seq first
    try sock_send.sendTo(pkt_hi, target);
    try testPollReady(sock_recv.fd);

    var recv_buf: [4096]u8 = undefined;
    const r1 = try peer.recv(&sock_recv, &recv_buf);
    try std.testing.expect(r1 != null);
    try std.testing.expect(peer.max_recv_seq == 10);

    // Send lower seq — packet is dropped.
    const old_port = peer.addr.?.getPort();
    try sock_send.sendTo(pkt_lo, target);
    try testPollReady(sock_recv.fd);

    var recv_buf2: [4096]u8 = undefined;
    const r2 = try peer.recv(&sock_recv, &recv_buf2);
    try std.testing.expect(r2 == null);
    try std.testing.expect(peer.max_recv_seq == 10);
    try std.testing.expect(peer.addr.?.getPort() == old_port);
}

test "Roaming: verify addr updates on authentic packet" {
    const key = crypto.generateKey();
    var peer = Peer.init(key, .to_client);

    var sock_recv = try testBindIp4(60950, 60960);
    defer sock_recv.close();
    var sock_a = try testBindIp4(60960, 60970);
    defer sock_a.close();
    var sock_b = try testBindIp4(60970, 60980);
    defer sock_b.close();

    const target = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, sock_recv.bound_port);

    var buf1: [128]u8 = undefined;
    try sock_a.sendTo(try crypto.encodeDatagram(key, .to_server, 1, "from_a", &buf1), target);
    try testPollReady(sock_recv.fd);

    var rb1: [4096]u8 = undefined;
    _ = try peer.recv(&sock_recv, &rb1);
    const port_a = peer.addr.?.getPort();

    var buf2: [128]u8 = undefined;
    try sock_b.sendTo(try crypto.encodeDatagram(key, .to_server, 2, "from_b", &buf2), target);
    try testPollReady(sock_recv.fd);

    var rb2: [4096]u8 = undefined;
    _ = try peer.recv(&sock_recv, &rb2);
    const port_b = peer.addr.?.getPort();

    try std.testing.expect(port_a != port_b);
}

test "Heartbeat timing logic" {
    var peer = Peer.init(crypto.generateKey(), .to_server);
    const config = Config{};
    const now = nanoNow();

    peer.last_send_time_any = now;
    try std.testing.expect(!peer.shouldSendHeartbeat(now, config));

    const later = now + @as(i64, config.heartbeat_interval_ms) * std.time.ns_per_ms + 1;
    try std.testing.expect(peer.shouldSendHeartbeat(later, config));
}

test "Peer state transitions" {
    var peer = Peer.init(crypto.generateKey(), .to_server);
    const config = Config{};
    const now = nanoNow();
    peer.last_recv_time = now;

    try std.testing.expect(peer.updateState(now + 1000, config) == .connected);

    const after_hb = now + @as(i64, config.heartbeat_timeout_ms) * std.time.ns_per_ms + 1;
    try std.testing.expect(peer.updateState(after_hb, config) == .disconnected);

    peer.state = .connected;
    peer.last_recv_time = now;
    const after_alive = now + @as(i64, config.alive_timeout_ms) * std.time.ns_per_ms + 1;
    try std.testing.expect(peer.updateState(after_alive, config) == .dead);
}

test "RTT estimation basic sanity" {
    var peer = Peer.init(crypto.generateKey(), .to_server);

    // First measurement: 100ms
    peer.updateRtt(100_000);
    try std.testing.expect(peer.srtt_us.? == 100_000);
    try std.testing.expect(peer.rttvar_us.? == 50_000);
    try std.testing.expect(peer.rto_us() == 300_000);

    // Second measurement: 120ms
    peer.updateRtt(120_000);
    try std.testing.expect(peer.rttvar_us.? == 42_500);
    try std.testing.expect(peer.srtt_us.? == 102_500);

    // Third measurement: 50ms
    peer.updateRtt(50_000);
    try std.testing.expect(peer.rttvar_us.? == 45_000);
    try std.testing.expect(peer.srtt_us.? == 95_937);
}
