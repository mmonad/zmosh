const std = @import("std");

pub const Kind = enum {
    udp,
    quic,

    pub fn parse(s: []const u8) ?Kind {
        if (std.mem.eql(u8, s, "udp")) return .udp;
        if (std.mem.eql(u8, s, "quic")) return .quic;
        return null;
    }

    pub fn asString(self: Kind) []const u8 {
        return switch (self) {
            .udp => "udp",
            .quic => "quic",
        };
    }
};
