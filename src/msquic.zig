const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const build_options = @import("build_options");
const crypto = @import("crypto.zig");
const ipc = @import("ipc.zig");

const log = std.log.scoped(.msquic);

pub const ConnectInfo = struct {
    host: []const u8,
    port: u16,
    key: crypto.Key,
};

pub const ServeConfig = struct {
    port_range_start: u16 = 60000,
    port_range_end: u16 = 61000,
};

const enabled = build_options.enable_msquic;
const c = if (enabled)
    @cImport({
        @cInclude("msquic.h");
    })
else
    struct {};

const c_term = switch (builtin.os.tag) {
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

pub fn remoteAttachQuic(alloc: std.mem.Allocator, info: ConnectInfo) !void {
    if (!enabled) return error.MsQuicDisabled;
    return impl.remoteAttachQuic(alloc, info);
}

pub fn serveMainQuic(alloc: std.mem.Allocator, session_name: []const u8, config: ServeConfig) !void {
    if (!enabled) return error.MsQuicDisabled;
    return impl.serveMainQuic(alloc, session_name, config);
}

const impl = if (enabled) struct {
    const alpn = "zmosh";
    const app_name: [:0]const u8 = "zmosh";
    const auth_magic = "ZMQA";
    const auth_len = auth_magic.len + crypto.key_length;

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

    fn isStatusOk(status: c.QUIC_STATUS) bool {
        return status == c.QUIC_STATUS_SUCCESS;
    }

    fn getTerminalSize() ipc.Resize {
        var ws: c_term.struct_winsize = undefined;
        if (c_term.ioctl(posix.STDOUT_FILENO, c_term.TIOCGWINSZ, &ws) == 0 and ws.ws_row > 0 and ws.ws_col > 0) {
            return .{ .rows = ws.ws_row, .cols = ws.ws_col };
        }
        return .{ .rows = 24, .cols = 80 };
    }

    fn isKittyCtrlBackslash(buf: []const u8) bool {
        return std.mem.indexOf(u8, buf, "\x1b[92;5u") != null or
            std.mem.indexOf(u8, buf, "\x1b[92;5:1u") != null;
    }

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

    fn ptrFromContext(comptime T: type, context: ?*anyopaque) ?*T {
        const ctx = context orelse return null;
        return @ptrCast(@alignCast(ctx));
    }

    fn resolveSocketDir(alloc: std.mem.Allocator) ![]const u8 {
        if (posix.getenv("ZMX_DIR")) |zmxdir|
            return try alloc.dupe(u8, zmxdir);
        const tmpdir = std.mem.trimRight(u8, posix.getenv("TMPDIR") orelse "/tmp", "/");
        const uid = posix.getuid();
        if (posix.getenv("XDG_RUNTIME_DIR")) |xdg_runtime|
            return try std.fmt.allocPrint(alloc, "{s}/zmx", .{xdg_runtime});
        return try std.fmt.allocPrint(alloc, "{s}/zmx-{d}", .{ tmpdir, uid });
    }

    fn connectUnix(path: []const u8) !i32 {
        var unix_addr = try std.net.Address.initUnix(path);
        const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(fd);
        try posix.connect(fd, &unix_addr.any, unix_addr.getOsSockLen());
        const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
        _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.SOCK.NONBLOCK);
        return fd;
    }

    const SendContext = struct {
        alloc: std.mem.Allocator,
        bytes: []u8,
        buffer: c.QUIC_BUFFER,

        fn free(self: *SendContext) void {
            self.alloc.free(self.bytes);
            self.alloc.destroy(self);
        }
    };

    const Endpoint = struct {
        alloc: std.mem.Allocator,
        api: *const c.QUIC_API_TABLE,
        conn: ?c.HQUIC = null,
        stream: ?c.HQUIC = null,
        recv_mutex: std.Thread.Mutex = .{},
        recv_buf: std.ArrayList(u8),
        connected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn init(alloc: std.mem.Allocator, api: *const c.QUIC_API_TABLE) !Endpoint {
            return .{
                .alloc = alloc,
                .api = api,
                .recv_buf = try std.ArrayList(u8).initCapacity(alloc, 4096),
            };
        }

        fn deinit(self: *Endpoint) void {
            self.recv_buf.deinit(self.alloc);
        }

        fn onReceive(self: *Endpoint, event: *c.QUIC_STREAM_EVENT) void {
            const count = event.RECEIVE.BufferCount;
            if (count == 0) return;
            const buffers = event.RECEIVE.Buffers;
            self.recv_mutex.lock();
            defer self.recv_mutex.unlock();

            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const b = buffers[i];
                if (b.Length == 0) continue;
                self.recv_buf.appendSlice(self.alloc, b.Buffer[0..b.Length]) catch {
                    self.closed.store(true, .release);
                    return;
                };
            }
        }

        fn drainReceived(self: *Endpoint, out: *std.ArrayList(u8)) !void {
            self.recv_mutex.lock();
            defer self.recv_mutex.unlock();
            if (self.recv_buf.items.len == 0) return;
            try out.appendSlice(self.alloc, self.recv_buf.items);
            self.recv_buf.clearRetainingCapacity();
        }

        fn send(self: *Endpoint, data: []const u8) !void {
            const stream = self.stream orelse return error.NoStream;
            if (data.len == 0) return;

            var ctx = try self.alloc.create(SendContext);
            errdefer self.alloc.destroy(ctx);

            ctx.alloc = self.alloc;
            ctx.bytes = try self.alloc.alloc(u8, data.len);
            errdefer self.alloc.free(ctx.bytes);
            @memcpy(ctx.bytes, data);
            ctx.buffer = .{
                .Length = @intCast(data.len),
                .Buffer = ctx.bytes.ptr,
            };

            const status = self.api.StreamSend.?(stream, &ctx.buffer, 1, c.QUIC_SEND_FLAG_NONE, ctx);
            if (!isStatusOk(status)) {
                ctx.free();
                return error.QuicSendFailed;
            }
        }

        fn sendIpc(self: *Endpoint, tag: ipc.Tag, payload: []const u8) !void {
            const hdr = ipc.Header{ .tag = tag, .len = @intCast(payload.len) };
            try self.send(std.mem.asBytes(&hdr));
            if (payload.len > 0) {
                try self.send(payload);
            }
        }
    };

    const ClientState = struct {
        alloc: std.mem.Allocator,
        api: *const c.QUIC_API_TABLE,
        registration: c.HQUIC,
        configuration: c.HQUIC,
        endpoint: Endpoint,

        fn init(alloc: std.mem.Allocator) !ClientState {
            var api: *const c.QUIC_API_TABLE = undefined;
            const api_ptr: [*c]?*const anyopaque = @ptrCast(&api);
            if (!isStatusOk(c.MsQuicOpenVersion(c.QUIC_API_VERSION_2, api_ptr))) {
                return error.MsQuicOpenFailed;
            }

            var registration: c.HQUIC = undefined;
            const reg_cfg = c.QUIC_REGISTRATION_CONFIG{
                .AppName = app_name.ptr,
                .ExecutionProfile = c.QUIC_EXECUTION_PROFILE_LOW_LATENCY,
            };
            if (!isStatusOk(api.RegistrationOpen.?(&reg_cfg, &registration))) {
                c.MsQuicClose(api);
                return error.MsQuicRegistrationFailed;
            }
            errdefer api.RegistrationClose.?(registration);
            errdefer c.MsQuicClose(api);

            var alpn_buf = c.QUIC_BUFFER{
                .Length = alpn.len,
                .Buffer = @constCast(alpn.ptr),
            };

            var settings: c.QUIC_SETTINGS = std.mem.zeroes(c.QUIC_SETTINGS);
            settings.IdleTimeoutMs = 30_000;
            settings.IsSet.IdleTimeoutMs = 1;
            settings.KeepAliveIntervalMs = 2_000;
            settings.IsSet.KeepAliveIntervalMs = 1;

            var configuration: c.HQUIC = undefined;
            if (!isStatusOk(api.ConfigurationOpen.?(registration, &alpn_buf, 1, &settings, @sizeOf(c.QUIC_SETTINGS), null, &configuration))) {
                return error.MsQuicConfigurationFailed;
            }
            errdefer api.ConfigurationClose.?(configuration);

            var cred: c.QUIC_CREDENTIAL_CONFIG = std.mem.zeroes(c.QUIC_CREDENTIAL_CONFIG);
            cred.Type = c.QUIC_CREDENTIAL_TYPE_NONE;
            cred.Flags = c.QUIC_CREDENTIAL_FLAG_CLIENT | c.QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
            if (!isStatusOk(api.ConfigurationLoadCredential.?(configuration, &cred))) {
                return error.MsQuicCredentialLoadFailed;
            }

            var endpoint = try Endpoint.init(alloc, api);
            errdefer endpoint.deinit();

            var connection: c.HQUIC = undefined;
            if (!isStatusOk(api.ConnectionOpen.?(registration, clientConnectionCallback, null, &connection))) {
                return error.MsQuicConnectionOpenFailed;
            }
            endpoint.conn = connection;

            return .{
                .alloc = alloc,
                .api = api,
                .registration = registration,
                .configuration = configuration,
                .endpoint = endpoint,
            };
        }

        fn start(self: *ClientState, host: []const u8, port: u16) !void {
            const conn = self.endpoint.conn orelse return error.MsQuicNoConnection;
            self.api.SetCallbackHandler.?(conn, @ptrCast(&clientConnectionCallback), &self.endpoint);

            const host_z = try self.alloc.dupeZ(u8, host);
            defer self.alloc.free(host_z);

            if (!isStatusOk(self.api.ConnectionStart.?(conn, self.configuration, c.QUIC_ADDRESS_FAMILY_UNSPEC, host_z.ptr, port))) {
                return error.MsQuicConnectionStartFailed;
            }
        }

        fn deinit(self: *ClientState) void {
            if (self.endpoint.stream) |stream| {
                self.api.StreamShutdown.?(stream, c.QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            }
            if (self.endpoint.conn) |conn| {
                self.api.ConnectionShutdown.?(conn, c.QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
                self.api.ConnectionClose.?(conn);
            }
            self.api.ConfigurationClose.?(self.configuration);
            self.api.RegistrationClose.?(self.registration);
            c.MsQuicClose(self.api);
            self.endpoint.deinit();
        }

        fn maybeOpenStream(self: *ClientState) !void {
            if (!self.endpoint.connected.load(.acquire)) return;
            if (self.endpoint.stream != null) return;
            const conn = self.endpoint.conn orelse return;

            var stream: c.HQUIC = undefined;
            if (!isStatusOk(self.api.StreamOpen.?(conn, c.QUIC_STREAM_OPEN_FLAG_NONE, clientStreamCallback, &self.endpoint, &stream))) {
                return error.MsQuicStreamOpenFailed;
            }

            if (!isStatusOk(self.api.StreamStart.?(stream, c.QUIC_STREAM_START_FLAG_NONE))) {
                self.api.StreamClose.?(stream);
                return error.MsQuicStreamStartFailed;
            }

            self.endpoint.stream = stream;
        }
    };

    const ServerState = struct {
        alloc: std.mem.Allocator,
        api: *const c.QUIC_API_TABLE,
        registration: c.HQUIC,
        configuration: c.HQUIC,
        listener: c.HQUIC,
        endpoint: Endpoint,
        key: crypto.Key,
        bound_port: u16,

        unix_fd: i32,
        unix_read_buf: ipc.SocketBuffer,
        unix_write_buf: std.ArrayList(u8),
        inbound_buf: std.ArrayList(u8),
        authenticated: bool = false,

        fn init(
            alloc: std.mem.Allocator,
            session_name: []const u8,
        ) !ServerState {
            const socket_dir = try resolveSocketDir(alloc);
            defer alloc.free(socket_dir);
            const socket_path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ socket_dir, session_name });
            defer alloc.free(socket_path);

            const unix_fd = try connectUnix(socket_path);
            errdefer posix.close(unix_fd);

            var api: *const c.QUIC_API_TABLE = undefined;
            const api_ptr: [*c]?*const anyopaque = @ptrCast(&api);
            if (!isStatusOk(c.MsQuicOpenVersion(c.QUIC_API_VERSION_2, api_ptr))) {
                return error.MsQuicOpenFailed;
            }

            var registration: c.HQUIC = undefined;
            const reg_cfg = c.QUIC_REGISTRATION_CONFIG{
                .AppName = app_name.ptr,
                .ExecutionProfile = c.QUIC_EXECUTION_PROFILE_LOW_LATENCY,
            };
            if (!isStatusOk(api.RegistrationOpen.?(&reg_cfg, &registration))) {
                c.MsQuicClose(api);
                return error.MsQuicRegistrationFailed;
            }
            errdefer api.RegistrationClose.?(registration);
            errdefer c.MsQuicClose(api);

            var alpn_buf = c.QUIC_BUFFER{
                .Length = alpn.len,
                .Buffer = @constCast(alpn.ptr),
            };

            var settings: c.QUIC_SETTINGS = std.mem.zeroes(c.QUIC_SETTINGS);
            settings.PeerBidiStreamCount = 1;
            settings.IsSet.PeerBidiStreamCount = 1;
            settings.IdleTimeoutMs = 30_000;
            settings.IsSet.IdleTimeoutMs = 1;

            var configuration: c.HQUIC = undefined;
            if (!isStatusOk(api.ConfigurationOpen.?(registration, &alpn_buf, 1, &settings, @sizeOf(c.QUIC_SETTINGS), null, &configuration))) {
                return error.MsQuicConfigurationFailed;
            }
            errdefer api.ConfigurationClose.?(configuration);

            const cert_file = posix.getenv("ZMOSH_QUIC_CERT_FILE") orelse return error.MsQuicCertFileMissing;
            const key_file = posix.getenv("ZMOSH_QUIC_KEY_FILE") orelse return error.MsQuicKeyFileMissing;

            var cert = c.QUIC_CERTIFICATE_FILE{
                .PrivateKeyFile = key_file.ptr,
                .CertificateFile = cert_file.ptr,
            };
            var cred: c.QUIC_CREDENTIAL_CONFIG = std.mem.zeroes(c.QUIC_CREDENTIAL_CONFIG);
            cred.Type = c.QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            cred.CertificateFile = &cert;

            if (!isStatusOk(api.ConfigurationLoadCredential.?(configuration, &cred))) {
                return error.MsQuicCredentialLoadFailed;
            }

            var endpoint = try Endpoint.init(alloc, api);
            errdefer endpoint.deinit();

            var listener: c.HQUIC = undefined;
            if (!isStatusOk(api.ListenerOpen.?(registration, serverListenerCallback, null, &listener))) {
                return error.MsQuicListenerOpenFailed;
            }

            return .{
                .alloc = alloc,
                .api = api,
                .registration = registration,
                .configuration = configuration,
                .listener = listener,
                .endpoint = endpoint,
                .key = crypto.generateKey(),
                .bound_port = 0,
                .unix_fd = unix_fd,
                .unix_read_buf = try ipc.SocketBuffer.init(alloc),
                .unix_write_buf = try std.ArrayList(u8).initCapacity(alloc, 4096),
                .inbound_buf = try std.ArrayList(u8).initCapacity(alloc, 4096),
            };
        }

        fn start(self: *ServerState, config: ServeConfig) !void {
            var alpn_buf = c.QUIC_BUFFER{
                .Length = alpn.len,
                .Buffer = @constCast(alpn.ptr),
            };

            self.api.SetCallbackHandler.?(self.listener, @ptrCast(&serverListenerCallback), self);

            var addr: c.QUIC_ADDR = std.mem.zeroes(c.QUIC_ADDR);
            c.QuicAddrSetFamily(&addr, c.QUIC_ADDRESS_FAMILY_UNSPEC);

            var port = config.port_range_start;
            while (port < config.port_range_end) : (port += 1) {
                c.QuicAddrSetPort(&addr, port);
                const status = self.api.ListenerStart.?(self.listener, &alpn_buf, 1, &addr);
                if (isStatusOk(status)) {
                    self.bound_port = port;
                    break;
                }
            }

            if (self.bound_port == 0) {
                return error.AddressInUse;
            }
        }

        fn deinit(self: *ServerState) void {
            if (self.endpoint.stream) |stream| {
                self.api.StreamShutdown.?(stream, c.QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            }
            if (self.endpoint.conn) |conn| {
                self.api.ConnectionShutdown.?(conn, c.QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
                self.api.ConnectionClose.?(conn);
            }
            self.api.ListenerClose.?(self.listener);
            self.api.ConfigurationClose.?(self.configuration);
            self.api.RegistrationClose.?(self.registration);
            c.MsQuicClose(self.api);

            posix.close(self.unix_fd);
            self.unix_read_buf.deinit();
            self.unix_write_buf.deinit(self.alloc);
            self.inbound_buf.deinit(self.alloc);
            self.endpoint.deinit();
        }

        fn processInbound(self: *ServerState) !void {
            var scratch = try std.ArrayList(u8).initCapacity(self.alloc, 1024);
            defer scratch.deinit(self.alloc);

            try self.endpoint.drainReceived(&scratch);
            if (scratch.items.len == 0) return;

            try self.inbound_buf.appendSlice(self.alloc, scratch.items);

            if (!self.authenticated and self.inbound_buf.items.len >= auth_len) {
                const got = self.inbound_buf.items[0..auth_len];
                const key_bytes = got[auth_magic.len..auth_len];
                if (!std.mem.eql(u8, got[0..auth_magic.len], auth_magic) or !std.mem.eql(u8, key_bytes, &self.key)) {
                    log.warn("quic auth failed", .{});
                    return error.AuthenticationFailed;
                }

                self.authenticated = true;
                try self.inbound_buf.replaceRange(self.alloc, 0, auth_len, &[_]u8{});
                log.info("quic client authenticated", .{});
            }

            if (self.authenticated and self.inbound_buf.items.len > 0) {
                try self.unix_write_buf.appendSlice(self.alloc, self.inbound_buf.items);
                self.inbound_buf.clearRetainingCapacity();
            }
        }

        fn run(self: *ServerState) !void {
            while (true) {
                self.processInbound() catch |err| {
                    if (err == error.AuthenticationFailed) {
                        return;
                    }
                    return err;
                };

                if (!self.authenticated or self.endpoint.stream == null) {
                    std.Thread.sleep(25 * std.time.ns_per_ms);
                    continue;
                }

                var poll_fds: [2]posix.pollfd = undefined;
                var unix_events: i16 = posix.POLL.IN;
                if (self.unix_write_buf.items.len > 0) {
                    unix_events |= posix.POLL.OUT;
                }
                poll_fds[0] = .{ .fd = self.unix_fd, .events = unix_events, .revents = 0 };

                _ = posix.poll(poll_fds[0..1], 100) catch |err| {
                    if (err == error.Interrupted) continue;
                    return err;
                };

                if (poll_fds[0].revents & posix.POLL.IN != 0) {
                    const n = self.unix_read_buf.read(self.unix_fd) catch |err| {
                        if (err == error.WouldBlock) {
                            continue;
                        }
                        return err;
                    };
                    if (n == 0) {
                        const hdr = ipc.Header{ .tag = .SessionEnd, .len = 0 };
                        self.endpoint.send(std.mem.asBytes(&hdr)) catch {};
                        return;
                    }

                    while (self.unix_read_buf.next()) |msg| {
                        try self.endpoint.sendIpc(msg.header.tag, msg.payload);
                    }
                }

                if (poll_fds[0].revents & posix.POLL.OUT != 0) {
                    if (self.unix_write_buf.items.len > 0) {
                        const written = posix.write(self.unix_fd, self.unix_write_buf.items) catch |err| blk: {
                            if (err == error.WouldBlock) break :blk 0;
                            return err;
                        };
                        if (written > 0) {
                            try self.unix_write_buf.replaceRange(self.alloc, 0, written, &[_]u8{});
                        }
                    }
                }

                if (poll_fds[0].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                    return;
                }
            }
        }
    };

    fn freeSendContext(context: ?*anyopaque) void {
        if (context) |ctx| {
            const send_ctx: *SendContext = @ptrCast(@alignCast(ctx));
            send_ctx.free();
        }
    }

    fn clientConnectionCallback(connection: c.HQUIC, context: ?*anyopaque, event: [*c]c.QUIC_CONNECTION_EVENT) callconv(.c) c.QUIC_STATUS {
        const endpoint = ptrFromContext(Endpoint, context) orelse return c.QUIC_STATUS_SUCCESS;

        switch (event.*.Type) {
            c.QUIC_CONNECTION_EVENT_CONNECTED => {
                endpoint.connected.store(true, .release);
                endpoint.closed.store(false, .release);
            },
            c.QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED => {
                endpoint.stream = event.*.PEER_STREAM_STARTED.Stream;
                endpoint.api.SetCallbackHandler.?(event.*.PEER_STREAM_STARTED.Stream, @ptrCast(&clientStreamCallback), endpoint);
            },
            c.QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE => {
                endpoint.connected.store(false, .release);
                endpoint.closed.store(true, .release);
                if (!event.*.SHUTDOWN_COMPLETE.AppCloseInProgress) {
                    endpoint.api.ConnectionClose.?(connection);
                }
                endpoint.conn = null;
            },
            else => {},
        }

        return c.QUIC_STATUS_SUCCESS;
    }

    fn clientStreamCallback(stream: c.HQUIC, context: ?*anyopaque, event: [*c]c.QUIC_STREAM_EVENT) callconv(.c) c.QUIC_STATUS {
        const endpoint = ptrFromContext(Endpoint, context) orelse return c.QUIC_STATUS_SUCCESS;
        switch (event.*.Type) {
            c.QUIC_STREAM_EVENT_RECEIVE => {
                endpoint.onReceive(event);
            },
            c.QUIC_STREAM_EVENT_SEND_COMPLETE => {
                freeSendContext(event.*.SEND_COMPLETE.ClientContext);
            },
            c.QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE => {
                endpoint.closed.store(true, .release);
                if (!event.*.SHUTDOWN_COMPLETE.AppCloseInProgress) {
                    endpoint.api.StreamClose.?(stream);
                }
                endpoint.stream = null;
            },
            else => {},
        }
        return c.QUIC_STATUS_SUCCESS;
    }

    fn serverListenerCallback(_: c.HQUIC, context: ?*anyopaque, event: [*c]c.QUIC_LISTENER_EVENT) callconv(.c) c.QUIC_STATUS {
        const self = ptrFromContext(ServerState, context) orelse return c.QUIC_STATUS_INVALID_STATE;
        switch (event.*.Type) {
            c.QUIC_LISTENER_EVENT_NEW_CONNECTION => {
                const conn = event.*.NEW_CONNECTION.Connection;
                self.endpoint.conn = conn;
                self.endpoint.stream = null;
                self.endpoint.connected.store(false, .release);
                self.endpoint.closed.store(false, .release);
                self.authenticated = false;
                self.inbound_buf.clearRetainingCapacity();

                self.api.SetCallbackHandler.?(conn, @ptrCast(&serverConnectionCallback), self);
                return self.api.ConnectionSetConfiguration.?(conn, self.configuration);
            },
            else => return c.QUIC_STATUS_SUCCESS,
        }
    }

    fn serverConnectionCallback(connection: c.HQUIC, context: ?*anyopaque, event: [*c]c.QUIC_CONNECTION_EVENT) callconv(.c) c.QUIC_STATUS {
        const self = ptrFromContext(ServerState, context) orelse return c.QUIC_STATUS_SUCCESS;
        switch (event.*.Type) {
            c.QUIC_CONNECTION_EVENT_CONNECTED => {
                self.endpoint.connected.store(true, .release);
            },
            c.QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED => {
                self.endpoint.stream = event.*.PEER_STREAM_STARTED.Stream;
                self.api.SetCallbackHandler.?(event.*.PEER_STREAM_STARTED.Stream, @ptrCast(&serverStreamCallback), &self.endpoint);
            },
            c.QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE => {
                self.endpoint.connected.store(false, .release);
                self.endpoint.closed.store(true, .release);
                self.authenticated = false;
                if (!event.*.SHUTDOWN_COMPLETE.AppCloseInProgress) {
                    self.api.ConnectionClose.?(connection);
                }
                self.endpoint.conn = null;
                self.endpoint.stream = null;
            },
            else => {},
        }
        return c.QUIC_STATUS_SUCCESS;
    }

    fn serverStreamCallback(stream: c.HQUIC, context: ?*anyopaque, event: [*c]c.QUIC_STREAM_EVENT) callconv(.c) c.QUIC_STATUS {
        const endpoint = ptrFromContext(Endpoint, context) orelse return c.QUIC_STATUS_SUCCESS;
        switch (event.*.Type) {
            c.QUIC_STREAM_EVENT_RECEIVE => {
                endpoint.onReceive(event);
            },
            c.QUIC_STREAM_EVENT_SEND_COMPLETE => {
                freeSendContext(event.*.SEND_COMPLETE.ClientContext);
            },
            c.QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE => {
                endpoint.closed.store(true, .release);
                if (!event.*.SHUTDOWN_COMPLETE.AppCloseInProgress) {
                    endpoint.api.StreamClose.?(stream);
                }
                endpoint.stream = null;
            },
            else => {},
        }
        return c.QUIC_STATUS_SUCCESS;
    }

    fn sendAuth(endpoint: *Endpoint, key: crypto.Key) !void {
        var auth_buf: [auth_len]u8 = undefined;
        @memcpy(auth_buf[0..auth_magic.len], auth_magic);
        @memcpy(auth_buf[auth_magic.len..auth_len], &key);
        try endpoint.send(&auth_buf);
    }

    pub fn remoteAttachQuic(alloc: std.mem.Allocator, info: ConnectInfo) !void {
        var client = try ClientState.init(alloc);
        defer client.deinit();
        try client.start(info.host, info.port);

        var orig_termios: c_term.termios = undefined;
        _ = c_term.tcgetattr(posix.STDIN_FILENO, &orig_termios);
        defer {
            _ = c_term.tcsetattr(posix.STDIN_FILENO, c_term.TCSAFLUSH, &orig_termios);
            const restore_seq = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l" ++
                "\x1b[?2004l\x1b[?1004l\x1b[?1049l" ++
                "\x1b[?25h";
            _ = posix.write(posix.STDOUT_FILENO, restore_seq) catch {};
        }

        var raw_termios = orig_termios;
        c_term.cfmakeraw(&raw_termios);
        raw_termios.c_cc[c_term.VLNEXT] = c_term._POSIX_VDISABLE;
        raw_termios.c_cc[c_term.VQUIT] = c_term._POSIX_VDISABLE;
        raw_termios.c_cc[c_term.VMIN] = 1;
        raw_termios.c_cc[c_term.VTIME] = 0;
        _ = c_term.tcsetattr(posix.STDIN_FILENO, c_term.TCSANOW, &raw_termios);

        _ = try posix.write(posix.STDOUT_FILENO, "\x1b[2J\x1b[H");

        setupSigwinchHandler();

        const stdin_flags = try posix.fcntl(posix.STDIN_FILENO, posix.F.GETFL, 0);
        _ = try posix.fcntl(posix.STDIN_FILENO, posix.F.SETFL, stdin_flags | posix.SOCK.NONBLOCK);

        var did_auth_and_init = false;
        var session_ended = false;

        var stdout_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
        defer stdout_buf.deinit(alloc);

        var inbound = try std.ArrayList(u8).initCapacity(alloc, 4096);
        defer inbound.deinit(alloc);

        while (true) {
            if (client.endpoint.closed.load(.acquire)) {
                _ = posix.write(posix.STDOUT_FILENO, "\r\nzmosh: QUIC connection closed\r\n") catch {};
                return;
            }

            client.maybeOpenStream() catch {};

            if (!did_auth_and_init and client.endpoint.stream != null) {
                try sendAuth(&client.endpoint, info.key);
                const size = getTerminalSize();
                var init_buf: [128]u8 = undefined;
                const init_ipc = buildIpcBytes(.Init, std.mem.asBytes(&size), &init_buf);
                try client.endpoint.send(init_ipc);
                did_auth_and_init = true;
            }

            if (did_auth_and_init and sigwinch_received.swap(false, .acq_rel)) {
                const new_size = getTerminalSize();
                var resize_buf: [128]u8 = undefined;
                const resize_ipc = buildIpcBytes(.Resize, std.mem.asBytes(&new_size), &resize_buf);
                client.endpoint.send(resize_ipc) catch {};
            }

            try client.endpoint.drainReceived(&inbound);

            var offset: usize = 0;
            while (offset < inbound.items.len) {
                const remaining = inbound.items[offset..];
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
            if (offset > 0) {
                try inbound.replaceRange(alloc, 0, offset, &[_]u8{});
            }

            var poll_fds: [2]posix.pollfd = undefined;
            var poll_count: usize = 1;
            poll_fds[0] = .{ .fd = posix.STDIN_FILENO, .events = posix.POLL.IN, .revents = 0 };
            if (stdout_buf.items.len > 0) {
                poll_fds[1] = .{ .fd = posix.STDOUT_FILENO, .events = posix.POLL.OUT, .revents = 0 };
                poll_count = 2;
            }

            _ = posix.poll(poll_fds[0..poll_count], 100) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };

            if (poll_fds[0].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR) != 0) {
                var input_raw: [4096]u8 = undefined;
                const n_opt: ?usize = posix.read(posix.STDIN_FILENO, &input_raw) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk null;
                    return err;
                };
                if (n_opt) |n| {
                    if (n > 0) {
                        if (input_raw[0] == 0x1C or isKittyCtrlBackslash(input_raw[0..n])) {
                            var detach_buf: [128]u8 = undefined;
                            const detach_ipc = buildIpcBytes(.Detach, "", &detach_buf);
                            client.endpoint.send(detach_ipc) catch {};
                            return;
                        }
                        if (did_auth_and_init) {
                            var ipc_buf: [4096 + @sizeOf(ipc.Header)]u8 = undefined;
                            const input_ipc = buildIpcBytes(.Input, input_raw[0..n], &ipc_buf);
                            client.endpoint.send(input_ipc) catch {};
                        }
                    } else {
                        return;
                    }
                }
            }

            if (poll_count == 2 and poll_fds[1].revents & posix.POLL.OUT != 0) {
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
                if (stdout_buf.items.len > 0) {
                    _ = posix.write(posix.STDOUT_FILENO, stdout_buf.items) catch {};
                }
                _ = posix.write(posix.STDOUT_FILENO, "\r\nzmosh: remote session ended\r\n") catch {};
                return;
            }
        }
    }

    pub fn serveMainQuic(alloc: std.mem.Allocator, session_name: []const u8, config: ServeConfig) !void {
        var server = try ServerState.init(alloc, session_name);
        defer server.deinit();
        try server.start(config);

        const encoded_key = crypto.keyToBase64(server.key);
        var out_buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&out_buf, "ZMX_CONNECT quic {d} {s}\n", .{ server.bound_port, encoded_key }) catch unreachable;
        _ = try posix.write(posix.STDOUT_FILENO, line);
        posix.close(posix.STDOUT_FILENO);

        return server.run();
    }
} else struct {};
