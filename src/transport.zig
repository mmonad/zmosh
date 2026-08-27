const std = @import("std");
const ipc = @import("ipc.zig");

pub const version: u8 = 2;
pub const max_payload_len: usize = 1100;
const header_len: usize = 20;
pub const reliable_window_size: u32 = 32;
pub const output_reorder_window: u32 = 32;
const snapshot_header_len: usize = 17;
pub const max_snapshot_chunk_len: usize = max_payload_len - snapshot_header_len;

pub const Channel = enum(u8) {
    heartbeat = 0,
    reliable_ipc = 1,
    output = 2,
    control = 3,
    snapshot = 4,
};

pub const Control = enum(u8) {
    resync_request = 1,
};

pub const Packet = struct {
    channel: Channel,
    seq: u32,
    ack: u32,
    ack_bits: u32,
    payload: []const u8,
};

pub const ReliableAction = enum {
    accept,
    duplicate,
    stale,
};

pub const OutputAction = enum {
    accept,
    duplicate,
    stale,
    gap,
};

pub const RecvState = struct {
    latest: u32 = 0,
    mask: u32 = 0,
    has_latest: bool = false,

    pub fn onReliable(self: *RecvState, seq: u32) ReliableAction {
        if (!self.has_latest) {
            self.latest = seq;
            self.mask = 0;
            self.has_latest = true;
            return .accept;
        }

        if (seq > self.latest) {
            const shift = seq - self.latest;
            if (shift > 32) {
                self.mask = 0;
            } else if (shift == 32) {
                self.mask = @as(u32, 1) << 31;
            } else {
                self.mask <<= @intCast(shift);
                self.mask |= @as(u32, 1) << @intCast(shift - 1);
            }
            self.latest = seq;
            return .accept;
        }

        const diff = self.latest - seq;
        if (diff == 0) return .duplicate;
        if (diff > 32) return .stale;

        const bit: u32 = @as(u32, 1) << @intCast(diff - 1);
        if (self.mask & bit != 0) return .duplicate;
        self.mask |= bit;
        return .accept;
    }

    pub fn ack(self: *const RecvState) u32 {
        return if (self.has_latest) self.latest else 0;
    }

    pub fn ackBits(self: *const RecvState) u32 {
        return if (self.has_latest) self.mask else 0;
    }
};

fn nextSequence(seq: u32) u32 {
    const next = seq +% 1;
    return if (next == 0) 1 else next;
}

pub const OwnedPacket = struct {
    alloc: std.mem.Allocator,
    channel: Channel,
    seq: u32,
    payload: []u8,

    pub fn deinit(self: OwnedPacket) void {
        self.alloc.free(self.payload);
    }
};

/// Selectively acknowledges reliable packets immediately, but exposes them to
/// the caller strictly in sequence order. The sender's matching 32-packet
/// flight window guarantees that a missing packet cannot fall out of the ACK
/// bitmap while later packets continue advancing.
pub const OrderedRecv = struct {
    alloc: std.mem.Allocator,
    ack_state: RecvState = .{},
    next_seq: u32 = 1,
    buffered: std.ArrayList(OwnedPacket),

    pub fn init(alloc: std.mem.Allocator) !OrderedRecv {
        return .{
            .alloc = alloc,
            .buffered = try std.ArrayList(OwnedPacket).initCapacity(alloc, reliable_window_size),
        };
    }

    pub fn deinit(self: *OrderedRecv) void {
        for (self.buffered.items) |packet| packet.deinit();
        self.buffered.deinit(self.alloc);
    }

    pub fn ack(self: *const OrderedRecv) u32 {
        return self.ack_state.ack();
    }

    pub fn ackBits(self: *const OrderedRecv) u32 {
        return self.ack_state.ackBits();
    }

    pub fn push(self: *OrderedRecv, packet: Packet) !ReliableAction {
        if (packet.seq == 0) return .stale;

        if (packet.seq < self.next_seq) {
            _ = self.ack_state.onReliable(packet.seq);
            return .duplicate;
        }

        if (packet.seq - self.next_seq >= reliable_window_size) {
            return .stale;
        }

        const action = self.ack_state.onReliable(packet.seq);
        if (action != .accept) return action;

        const payload = try self.alloc.dupe(u8, packet.payload);
        errdefer self.alloc.free(payload);
        try self.buffered.append(self.alloc, .{
            .alloc = self.alloc,
            .channel = packet.channel,
            .seq = packet.seq,
            .payload = payload,
        });
        return .accept;
    }

    pub fn popReady(self: *OrderedRecv) ?OwnedPacket {
        for (self.buffered.items, 0..) |packet, i| {
            if (packet.seq != self.next_seq) continue;
            const ready = self.buffered.swapRemove(i);
            self.next_seq = nextSequence(self.next_seq);
            return ready;
        }
        return null;
    }
};

pub const OutputRecvState = struct {
    const Buffered = struct {
        seq: u32,
        payload: []u8,
    };

    alloc: std.mem.Allocator,
    next_seq: u32 = 1,
    buffered: std.ArrayList(Buffered),
    gap_started_ns: ?i64 = null,

    pub fn init(alloc: std.mem.Allocator) !OutputRecvState {
        return .{
            .alloc = alloc,
            .buffered = try std.ArrayList(Buffered).initCapacity(alloc, output_reorder_window),
        };
    }

    pub fn deinit(self: *OutputRecvState) void {
        self.clear();
        self.buffered.deinit(self.alloc);
    }

    pub fn reset(self: *OutputRecvState, next_seq: u32) void {
        self.clear();
        self.next_seq = if (next_seq == 0) 1 else next_seq;
    }

    pub fn clear(self: *OutputRecvState) void {
        for (self.buffered.items) |item| self.alloc.free(item.payload);
        self.buffered.clearRetainingCapacity();
        self.gap_started_ns = null;
    }

    pub fn onPacket(self: *OutputRecvState, seq: u32, payload: []const u8, now_ns: i64) !OutputAction {
        if (seq == 0 or seq < self.next_seq) return .duplicate;

        const distance = seq - self.next_seq;
        if (distance >= output_reorder_window) return .gap;

        for (self.buffered.items) |item| {
            if (item.seq == seq) return .duplicate;
        }

        const owned = try self.alloc.dupe(u8, payload);
        errdefer self.alloc.free(owned);
        try self.buffered.append(self.alloc, .{ .seq = seq, .payload = owned });

        if (distance > 0 and self.gap_started_ns == null) {
            self.gap_started_ns = now_ns;
        }
        return .accept;
    }

    pub fn popReady(self: *OutputRecvState) ?[]u8 {
        for (self.buffered.items, 0..) |item, i| {
            if (item.seq != self.next_seq) continue;
            const ready = self.buffered.swapRemove(i).payload;
            self.next_seq = nextSequence(self.next_seq);
            return ready;
        }
        return null;
    }

    pub fn noteDrain(self: *OutputRecvState, made_progress: bool, now_ns: i64) void {
        if (self.buffered.items.len == 0) {
            self.gap_started_ns = null;
        } else if (made_progress) {
            self.gap_started_ns = now_ns;
        } else if (self.gap_started_ns == null) {
            self.gap_started_ns = now_ns;
        }
    }

    pub fn gapExpired(self: *const OutputRecvState, now_ns: i64, timeout_ns: i64) bool {
        const started = self.gap_started_ns orelse return false;
        return now_ns - started >= timeout_ns;
    }

    pub fn gapRemainingNs(self: *const OutputRecvState, now_ns: i64, timeout_ns: i64) ?i64 {
        const started = self.gap_started_ns orelse return null;
        return @max(@as(i64, 0), timeout_ns - (now_ns - started));
    }
};

pub const ReliableSend = struct {
    alloc: std.mem.Allocator,
    next_seq: u32 = 1,
    pending: std.ArrayList(Pending),
    pending_bytes: usize = 0,

    const Pending = struct {
        seq: u32,
        sent_ns: ?i64,
        retries: u8,
        packet: []u8,
    };

    pub fn init(alloc: std.mem.Allocator) !ReliableSend {
        return .{
            .alloc = alloc,
            .pending = try std.ArrayList(Pending).initCapacity(alloc, 16),
        };
    }

    pub fn deinit(self: *ReliableSend) void {
        for (self.pending.items) |p| {
            self.alloc.free(p.packet);
        }
        self.pending.deinit(self.alloc);
    }

    pub fn hasPending(self: *const ReliableSend) bool {
        return self.pending.items.len > 0;
    }

    pub fn pendingBytes(self: *const ReliableSend) usize {
        return self.pending_bytes;
    }

    pub fn queue(
        self: *ReliableSend,
        channel: Channel,
        payload: []const u8,
        ack_seq: u32,
        ack_bits: u32,
    ) !u32 {
        const seq = self.next_seq;
        self.next_seq = nextSequence(self.next_seq);

        const packet = try self.alloc.alloc(u8, header_len + payload.len);
        errdefer self.alloc.free(packet);
        writeHeader(packet[0..header_len], channel, seq, ack_seq, ack_bits, payload.len);
        if (payload.len > 0) {
            @memcpy(packet[header_len..], payload);
        }

        try self.pending.append(self.alloc, .{
            .seq = seq,
            .sent_ns = null,
            .retries = 0,
            .packet = packet,
        });
        self.pending_bytes += packet.len;

        return seq;
    }

    pub fn ack(self: *ReliableSend, ack_seq: u32, ack_bits: u32) void {
        var i: usize = self.pending.items.len;
        while (i > 0) {
            i -= 1;
            const p = self.pending.items[i];
            if (isAcked(p.seq, ack_seq, ack_bits)) {
                self.pending_bytes -= p.packet.len;
                self.alloc.free(p.packet);
                _ = self.pending.swapRemove(i);
            }
        }
    }

    pub fn collectTransmissions(
        self: *ReliableSend,
        alloc: std.mem.Allocator,
        now_ns: i64,
        rto_us: i64,
    ) !std.ArrayList([]const u8) {
        var out = try std.ArrayList([]const u8).initCapacity(alloc, 4);
        const interval_ns = @max(@as(i64, 1), rto_us) * std.time.ns_per_us;

        var oldest_seq = self.next_seq;
        for (self.pending.items) |p| oldest_seq = @min(oldest_seq, p.seq);

        for (self.pending.items) |*p| {
            if (p.seq - oldest_seq >= reliable_window_size) continue;

            if (p.sent_ns) |sent_ns| {
                if (now_ns - sent_ns < interval_ns) continue;
                p.retries +%= 1;
            }

            p.sent_ns = now_ns;
            try out.append(alloc, p.packet);
        }

        return out;
    }

    pub fn hasPendingRange(self: *const ReliableSend, first: u32, last: u32) bool {
        for (self.pending.items) |p| {
            if (p.seq >= first and p.seq <= last) return true;
        }
        return false;
    }

    fn isAcked(seq: u32, ack_seq: u32, ack_bits: u32) bool {
        if (ack_seq == 0) return false;
        if (seq == ack_seq) return true;
        if (seq > ack_seq) return false;

        const diff = ack_seq - seq;
        if (diff == 0) return true;
        if (diff > 32) return false;

        const bit: u32 = @as(u32, 1) << @intCast(diff - 1);
        return (ack_bits & bit) != 0;
    }
};

pub const SnapshotKind = enum(u8) {
    begin = 1,
    chunk = 2,
    end = 3,
};

pub const SnapshotFrame = struct {
    kind: SnapshotKind,
    generation: u32,
    total_len: u32,
    offset: u32,
    resume_output_seq: u32,
    data: []const u8,
};

pub const SnapshotSeqRange = struct {
    first: u32,
    last: u32,
};

pub const CompletedSnapshot = struct {
    generation: u32,
    resume_output_seq: u32,
    data: []u8,

    pub fn deinit(self: CompletedSnapshot, alloc: std.mem.Allocator) void {
        alloc.free(self.data);
    }
};

pub const SnapshotAssembler = struct {
    alloc: std.mem.Allocator,
    data: std.ArrayList(u8),
    active: bool = false,
    generation: u32 = 0,
    total_len: u32 = 0,
    resume_output_seq: u32 = 1,

    pub fn init(alloc: std.mem.Allocator) !SnapshotAssembler {
        return .{
            .alloc = alloc,
            .data = try std.ArrayList(u8).initCapacity(alloc, 4096),
        };
    }

    pub fn deinit(self: *SnapshotAssembler) void {
        self.data.deinit(self.alloc);
    }

    pub fn reset(self: *SnapshotAssembler) void {
        self.data.clearRetainingCapacity();
        self.active = false;
    }

    pub fn accept(self: *SnapshotAssembler, frame: SnapshotFrame) !?CompletedSnapshot {
        switch (frame.kind) {
            .begin => {
                self.data.clearRetainingCapacity();
                self.active = true;
                self.generation = frame.generation;
                self.total_len = frame.total_len;
                self.resume_output_seq = if (frame.resume_output_seq == 0) 1 else frame.resume_output_seq;
                return null;
            },
            .chunk => {
                if (!self.active) return error.SnapshotNotStarted;
                if (frame.generation != self.generation or
                    frame.total_len != self.total_len or
                    frame.resume_output_seq != self.resume_output_seq)
                {
                    return error.SnapshotGenerationMismatch;
                }
                if (@as(usize, frame.offset) != self.data.items.len) return error.SnapshotOffsetMismatch;
                if (self.data.items.len + frame.data.len > @as(usize, self.total_len)) return error.SnapshotTooLong;
                try self.data.appendSlice(self.alloc, frame.data);
                return null;
            },
            .end => {
                if (!self.active) return error.SnapshotNotStarted;
                if (frame.generation != self.generation or
                    frame.total_len != self.total_len or
                    frame.resume_output_seq != self.resume_output_seq)
                {
                    return error.SnapshotGenerationMismatch;
                }
                if (frame.offset != self.total_len or self.data.items.len != @as(usize, self.total_len)) {
                    return error.SnapshotIncomplete;
                }

                const data = try self.data.toOwnedSlice(self.alloc);
                self.active = false;
                return .{
                    .generation = self.generation,
                    .resume_output_seq = self.resume_output_seq,
                    .data = data,
                };
            },
        }
    }
};

pub fn buildSnapshotFrame(frame: SnapshotFrame, out: []u8) ![]const u8 {
    const total = snapshot_header_len + frame.data.len;
    if (total > max_payload_len or out.len < total) return error.BufferTooSmall;

    out[0] = @intFromEnum(frame.kind);
    std.mem.writeInt(u32, out[1..5], frame.generation, .big);
    std.mem.writeInt(u32, out[5..9], frame.total_len, .big);
    std.mem.writeInt(u32, out[9..13], frame.offset, .big);
    std.mem.writeInt(u32, out[13..17], frame.resume_output_seq, .big);
    if (frame.data.len > 0) @memcpy(out[snapshot_header_len..total], frame.data);
    return out[0..total];
}

pub fn parseSnapshotFrame(payload: []const u8) !SnapshotFrame {
    if (payload.len < snapshot_header_len) return error.SnapshotFrameTooShort;
    const kind = std.meta.intToEnum(SnapshotKind, payload[0]) catch return error.InvalidSnapshotKind;
    const frame: SnapshotFrame = .{
        .kind = kind,
        .generation = std.mem.readInt(u32, payload[1..5], .big),
        .total_len = std.mem.readInt(u32, payload[5..9], .big),
        .offset = std.mem.readInt(u32, payload[9..13], .big),
        .resume_output_seq = std.mem.readInt(u32, payload[13..17], .big),
        .data = payload[snapshot_header_len..],
    };

    switch (kind) {
        .begin => if (frame.offset != 0 or frame.data.len != 0) return error.InvalidSnapshotBegin,
        .chunk => if (frame.data.len == 0) return error.InvalidSnapshotChunk,
        .end => if (frame.offset != frame.total_len or frame.data.len != 0) return error.InvalidSnapshotEnd,
    }
    return frame;
}

pub fn queueSnapshot(
    sender: *ReliableSend,
    generation: u32,
    snapshot: []const u8,
    resume_output_seq: u32,
    ack_seq: u32,
    ack_bits: u32,
) !SnapshotSeqRange {
    if (snapshot.len > std.math.maxInt(u32)) return error.SnapshotTooLarge;
    const total_len: u32 = @intCast(snapshot.len);
    var frame_buf: [max_payload_len]u8 = undefined;

    const begin = try buildSnapshotFrame(.{
        .kind = .begin,
        .generation = generation,
        .total_len = total_len,
        .offset = 0,
        .resume_output_seq = resume_output_seq,
        .data = "",
    }, &frame_buf);
    const first = try sender.queue(.snapshot, begin, ack_seq, ack_bits);

    var offset: usize = 0;
    while (offset < snapshot.len) {
        const end = @min(offset + max_snapshot_chunk_len, snapshot.len);
        const chunk = try buildSnapshotFrame(.{
            .kind = .chunk,
            .generation = generation,
            .total_len = total_len,
            .offset = @intCast(offset),
            .resume_output_seq = resume_output_seq,
            .data = snapshot[offset..end],
        }, &frame_buf);
        _ = try sender.queue(.snapshot, chunk, ack_seq, ack_bits);
        offset = end;
    }

    const end_frame = try buildSnapshotFrame(.{
        .kind = .end,
        .generation = generation,
        .total_len = total_len,
        .offset = total_len,
        .resume_output_seq = resume_output_seq,
        .data = "",
    }, &frame_buf);
    const last = try sender.queue(.snapshot, end_frame, ack_seq, ack_bits);
    return .{ .first = first, .last = last };
}

pub fn writeHeader(dst: []u8, channel: Channel, seq: u32, ack: u32, ack_bits: u32, payload_len: usize) void {
    std.debug.assert(dst.len >= header_len);
    std.debug.assert(payload_len <= std.math.maxInt(u16));

    dst[0] = version;
    dst[1] = @intFromEnum(channel);
    dst[2] = 0;
    dst[3] = 0;

    std.mem.writeInt(u32, dst[4..8], seq, .big);
    std.mem.writeInt(u32, dst[8..12], ack, .big);
    std.mem.writeInt(u32, dst[12..16], ack_bits, .big);
    std.mem.writeInt(u16, dst[16..18], @intCast(payload_len), .big);
    std.mem.writeInt(u16, dst[18..20], 0, .big);
}

pub fn parsePacket(data: []const u8) !Packet {
    if (data.len < header_len) return error.PacketTooShort;
    if (data[0] != version) return error.UnsupportedVersion;

    const channel_int = data[1];
    const channel = std.meta.intToEnum(Channel, channel_int) catch return error.InvalidChannel;

    const seq = std.mem.readInt(u32, data[4..8], .big);
    const ack = std.mem.readInt(u32, data[8..12], .big);
    const ack_bits = std.mem.readInt(u32, data[12..16], .big);
    const len = std.mem.readInt(u16, data[16..18], .big);

    if (data.len != header_len + len) return error.InvalidLength;

    return .{
        .channel = channel,
        .seq = seq,
        .ack = ack,
        .ack_bits = ack_bits,
        .payload = data[header_len..],
    };
}

pub fn buildUnreliable(
    channel: Channel,
    seq: u32,
    ack: u32,
    ack_bits: u32,
    payload: []const u8,
    out: []u8,
) ![]const u8 {
    const total = header_len + payload.len;
    if (out.len < total) return error.BufferTooSmall;
    writeHeader(out[0..header_len], channel, seq, ack, ack_bits, payload.len);
    if (payload.len > 0) {
        @memcpy(out[header_len..total], payload);
    }
    return out[0..total];
}

pub fn buildControl(control: Control, out: *[8]u8) []const u8 {
    out[0] = @intFromEnum(control);
    @memset(out[1..], 0);
    return out[0..1];
}

pub fn parseControl(payload: []const u8) !Control {
    if (payload.len < 1) return error.InvalidControl;
    return std.meta.intToEnum(Control, payload[0]) catch error.InvalidControl;
}

pub fn buildIpcBytes(tag: ipc.Tag, payload: []const u8, buf: []u8) []const u8 {
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

test "transport header round trip" {
    var buf: [64]u8 = undefined;
    const payload = "abc";
    const pkt = try buildUnreliable(.output, 7, 6, 0x55, payload, &buf);
    const parsed = try parsePacket(pkt);
    try std.testing.expect(parsed.channel == .output);
    try std.testing.expectEqual(@as(u32, 7), parsed.seq);
    try std.testing.expectEqual(@as(u32, 6), parsed.ack);
    try std.testing.expectEqual(@as(u32, 0x55), parsed.ack_bits);
    try std.testing.expectEqualStrings(payload, parsed.payload);
}

test "reliable recv window" {
    var recv = RecvState{};
    try std.testing.expect(recv.onReliable(10) == .accept);
    try std.testing.expect(recv.onReliable(9) == .accept);
    try std.testing.expect(recv.onReliable(9) == .duplicate);
    try std.testing.expect(recv.onReliable(11) == .accept);
    try std.testing.expectEqual(@as(u32, 11), recv.ack());
}

test "ordered reliable receive buffers reordering" {
    const alloc = std.testing.allocator;
    var recv = try OrderedRecv.init(alloc);
    defer recv.deinit();

    var packet_buf: [64]u8 = undefined;
    for ([_]u32{ 3, 1, 2 }) |seq| {
        var payload_buf: [8]u8 = undefined;
        const payload = try std.fmt.bufPrint(&payload_buf, "{d}", .{seq});
        const wire = try buildUnreliable(.reliable_ipc, seq, 0, 0, payload, &packet_buf);
        try std.testing.expect(try recv.push(try parsePacket(wire)) == .accept);
    }

    for ([_]u32{ 1, 2, 3 }) |seq| {
        const packet = recv.popReady().?;
        defer packet.deinit();
        var expected_buf: [8]u8 = undefined;
        const expected = try std.fmt.bufPrint(&expected_buf, "{d}", .{seq});
        try std.testing.expectEqualStrings(expected, packet.payload);
    }
    try std.testing.expect(recv.popReady() == null);
}

test "reliable send window stays pinned behind a missing packet" {
    const alloc = std.testing.allocator;
    var send = try ReliableSend.init(alloc);
    defer send.deinit();

    var seq: u32 = 1;
    while (seq <= 64) : (seq += 1) {
        _ = try send.queue(.control, "x", 0, 0);
    }

    var transmissions = try send.collectTransmissions(alloc, 1, 1000);
    defer transmissions.deinit(alloc);
    try std.testing.expectEqual(@as(usize, reliable_window_size), transmissions.items.len);

    // ACK 2..32 while leaving packet 1 missing. No later packet may leave the
    // sender until packet 1 is retransmitted and acknowledged.
    send.ack(32, 0x3fff_ffff);
    var early = try send.collectTransmissions(alloc, 500 * std.time.ns_per_us, 1000);
    defer early.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 0), early.items.len);

    var retry = try send.collectTransmissions(alloc, 2 * std.time.ns_per_ms, 1000);
    defer retry.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), retry.items.len);
    try std.testing.expectEqual(@as(u32, 1), (try parsePacket(retry.items[0])).seq);

    send.ack(32, 0x7fff_ffff);
    var second_window = try send.collectTransmissions(alloc, 2 * std.time.ns_per_ms + 1, 1000);
    defer second_window.deinit(alloc);
    try std.testing.expectEqual(@as(usize, reliable_window_size), second_window.items.len);
}

test "reliable send accounts queued bytes until acknowledgement" {
    const alloc = std.testing.allocator;
    var send = try ReliableSend.init(alloc);
    defer send.deinit();

    const first = try send.queue(.reliable_ipc, "abc", 0, 0);
    const first_bytes = header_len + 3;
    try std.testing.expectEqual(first_bytes, send.pendingBytes());

    const second = try send.queue(.reliable_ipc, "defgh", 0, 0);
    try std.testing.expectEqual(first_bytes + header_len + 5, send.pendingBytes());

    send.ack(first, 0);
    try std.testing.expectEqual(header_len + 5, send.pendingBytes());
    send.ack(second, 0);
    try std.testing.expectEqual(@as(usize, 0), send.pendingBytes());
}

test "large snapshot survives loss and reverse-order delivery" {
    const alloc = std.testing.allocator;
    const snapshot_len = 472_124;
    const snapshot = try alloc.alloc(u8, snapshot_len);
    defer alloc.free(snapshot);
    for (snapshot, 0..) |*byte, i| byte.* = @truncate(i *% 31 +% 7);

    var send = try ReliableSend.init(alloc);
    defer send.deinit();
    const range = try queueSnapshot(&send, 19, snapshot, 44, 0, 0);
    try std.testing.expect(range.last - range.first > reliable_window_size);

    var recv = try OrderedRecv.init(alloc);
    defer recv.deinit();
    var assembler = try SnapshotAssembler.init(alloc);
    defer assembler.deinit();
    var completed: ?CompletedSnapshot = null;
    defer if (completed) |value| value.deinit(alloc);

    var dropped_seven = false;
    var now: i64 = 1;
    var rounds: usize = 0;
    while (send.hasPending() and rounds < 1000) : (rounds += 1) {
        var batch = try send.collectTransmissions(alloc, now, 1000);
        defer batch.deinit(alloc);

        var i = batch.items.len;
        while (i > 0) {
            i -= 1;
            const packet = try parsePacket(batch.items[i]);
            if (packet.seq == 7 and !dropped_seven) {
                dropped_seven = true;
                continue;
            }

            _ = try recv.push(packet);
            while (recv.popReady()) |ready| {
                defer ready.deinit();
                const frame = try parseSnapshotFrame(ready.payload);
                if (try assembler.accept(frame)) |value| completed = value;
            }
        }

        send.ack(recv.ack(), recv.ackBits());
        now += 2 * std.time.ns_per_ms;
    }

    try std.testing.expect(dropped_seven);
    try std.testing.expect(!send.hasPending());
    try std.testing.expect(rounds < 1000);
    try std.testing.expect(completed != null);
    try std.testing.expectEqual(@as(u32, 19), completed.?.generation);
    try std.testing.expectEqual(@as(u32, 44), completed.?.resume_output_seq);
    try std.testing.expectEqualSlices(u8, snapshot, completed.?.data);
}

test "output receiver reorders a modest packet gap" {
    const alloc = std.testing.allocator;
    var out = try OutputRecvState.init(alloc);
    defer out.deinit();
    out.reset(1);

    try std.testing.expect(try out.onPacket(3, "three", 100) == .accept);
    try std.testing.expect(try out.onPacket(1, "one", 101) == .accept);

    const one = out.popReady().?;
    defer alloc.free(one);
    try std.testing.expectEqualStrings("one", one);
    out.noteDrain(true, 101);

    try std.testing.expect(try out.onPacket(2, "two", 102) == .accept);
    const two = out.popReady().?;
    defer alloc.free(two);
    const three = out.popReady().?;
    defer alloc.free(three);
    try std.testing.expectEqualStrings("two", two);
    try std.testing.expectEqualStrings("three", three);
    out.noteDrain(true, 102);
    try std.testing.expect(!out.gapExpired(1000, 50));

    out.reset(10);
    try std.testing.expect(try out.onPacket(11, "later", 200) == .accept);
    try std.testing.expect(!out.gapExpired(249, 50));
    try std.testing.expect(out.gapExpired(250, 50));
    try std.testing.expect(try out.onPacket(10 + output_reorder_window, "far", 250) == .gap);
}
