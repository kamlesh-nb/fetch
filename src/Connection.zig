const std = @import("std");
const tlsz = @import("tlsz");
const tls = tlsz.Tls;
const ciphers = tlsz.CipherSuites;
const clientHandshake = tlsz.ClientHandshake;
const R = tlsz.Record;

const Connection = @This();

pub const ReadError = error{
    TlsFailure,
    TlsAlert,
    ConnectionTimedOut,
    ConnectionResetByPeer,
    UnexpectedReadFailure,
    EndOfStream,
};

pub const WriteError = error{
    ConnectionResetByPeer,
    UnexpectedWriteFailure,
};

pub const ReaderError = std.net.Stream.ReadError || Connection.ReadError || tls.AlertDescription.Error || error{ ServerMalformedResponse, ServerInvalidVersion, AuthenticationFailed };


const InRecordState = ciphers.InRecordState(ciphers.CipherSuites.all);

const ReadState = union(enum) {
    none,
    in_record: struct {
        record_length: usize,
        index: usize = 0,
        state: InRecordState,
    },
};

client_seq: u64 = 1,
server_seq: u64 = 1,
read_state: ReadState = .none,
need_tls: bool = false,
stream: std.net.Stream = undefined,
handshake: clientHandshake = undefined,

pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream, host: []const u8, need_tls: bool) !Connection {
    return Connection{
        .need_tls = need_tls,
        .stream = stream,
        .handshake = if(need_tls)  try clientHandshake.init(allocator, stream, host) else undefined,
    };
}



fn lenOverhead(self: *const Connection) u16 {
    inline for (ciphers.CipherSuites.all) |cs| {
        if (self.handshake.csuite == cs.tag) {
            return cs.mac_length + cs.prefix_data_length;
        }
    }
    unreachable;
}

pub fn read(self: *Connection, buffer: []u8) ReaderError!usize {
    if (self.need_tls) {
        return try self.readTls(buffer);
    } else {
        return try self.stream.reader().read(buffer);
    }
}

pub fn write(self: *Connection, buffer: []const u8) std.net.Stream.WriteError!usize {
    if (self.need_tls) {
        return try self.writeTls(buffer);
    } else {
        return try self.stream.writer().write(buffer);
    }
}

pub fn readTls(self: *Connection, buffer: []u8) ReaderError!usize {
    const buf_size = 1024;

    switch (self.read_state) {
        .none => {
            const header = try R.readRecordHeader(self.stream.reader());

            const len_overhead = self.lenOverhead();

            const rec_length = header.len();
            if (rec_length < len_overhead)
                return error.ServerMalformedResponse;
            const len = rec_length - len_overhead;

            if ((header.tag() != 0x17 and header.tag() != 0x15) or
                (header.tag() == 0x15 and len != 2))
            {
                return error.ServerMalformedResponse;
            }

            inline for (ciphers.CipherSuites.all) |cs| {
                if (self.handshake.csuite == cs.tag) {
                    var prefix_data: [cs.prefix_data_length]u8 = undefined;
                    if (cs.prefix_data_length > 0) {
                        self.stream.reader().readNoEof(&prefix_data) catch |err| switch (err) {
                            error.EndOfStream => return error.ServerMalformedResponse,
                            else => |e| return e,
                        };
                    }
                    self.read_state = .{ .in_record = .{
                        .record_length = len,
                        .state = @unionInit(
                            InRecordState,
                            cs.name,
                            cs.init_state(prefix_data, self.server_seq, &self.handshake.key_data, header),
                        ),
                    } };
                }
            }

            if (header.tag() == 0x15) {
                var encrypted: [2]u8 = undefined;
                self.stream.reader().readNoEof(&encrypted) catch |err| switch (err) {
                    error.EndOfStream => return error.ServerMalformedResponse,
                    else => |e| return e,
                };

                var result: [2]u8 = undefined;
                inline for (ciphers.CipherSuites.all) |cs| {
                    if (self.handshake.csuite == cs.tag) {
                        // This decrypt call should always consume the whole record
                        cs.decrypt_part(
                            &self.handshake.key_data,
                            self.read_state.in_record.record_length,
                            &self.read_state.in_record.index,
                            &@field(self.read_state.in_record.state, cs.name),
                            &encrypted,
                            &result,
                        );
                        try cs.verify_mac(
                            self.stream.reader(),
                            self.read_state.in_record.record_length,
                            &@field(self.read_state.in_record.state, cs.name),
                        );
                    }
                }
                self.read_state = .none;
                self.server_seq += 1;
                // CloseNotify
                if (result[1] == 0)
                    return 0;
                // return alert_byte_to_error(result[1]);
            } else if (header.tag() == 0x17) {
                const curr_bytes = @min(@min(len, buf_size), buffer.len);
                // Partially decrypt the data.
                var encrypted: [buf_size]u8 = undefined;
                const actually_read = try self.stream.reader().read(encrypted[0..curr_bytes]);

                inline for (ciphers.CipherSuites.all) |cs| {
                    if (self.handshake.csuite == cs.tag) {
                        cs.decrypt_part(
                            &self.handshake.key_data,
                            self.read_state.in_record.record_length,
                            &self.read_state.in_record.index,
                            &@field(self.read_state.in_record.state, cs.name),
                            encrypted[0..actually_read],
                            buffer[0..actually_read],
                        );

                        if (self.read_state.in_record.index == self.read_state.in_record.record_length) {
                            try cs.verify_mac(
                                self.stream.reader(),
                                self.read_state.in_record.record_length,
                                &@field(self.read_state.in_record.state, cs.name),
                            );
                            self.server_seq += 1;
                            self.read_state = .none;
                        }
                    }
                }
                return actually_read;
            } else unreachable;
        },
        .in_record => |*in_record| {
            const curr_bytes = @min(@min(buf_size, buffer.len), in_record.record_length - in_record.index);
            // Partially decrypt the data.
            var encrypted: [buf_size]u8 = undefined;
            const actually_read = try self.stream.reader().read(encrypted[0..curr_bytes]);

            inline for (ciphers.CipherSuites.all) |cs| {
                if (self.handshake.csuite == cs.tag) {
                    cs.decrypt_part(
                        &self.handshake.key_data,
                        in_record.record_length,
                        &in_record.index,
                        &@field(in_record.state, cs.name),
                        encrypted[0..actually_read],
                        buffer[0..actually_read],
                    );

                    if (in_record.index == in_record.record_length) {
                        try cs.verify_mac(
                            self.stream.reader(),
                            in_record.record_length,
                            &@field(in_record.state, cs.name),
                        );
                        self.server_seq += 1;
                        self.read_state = .none;
                    }
                }
            }
            return actually_read;
        },
    }
    unreachable;
}

pub fn writeTls(self: *Connection, buffer: []const u8) std.net.Stream.WriteError!usize {
    if (buffer.len == 0) return 0;

    inline for (ciphers.CipherSuites.all) |cs| {
        if (self.handshake.csuite == cs.tag) {
            // @TODO Make this buffer size configurable
            const curr_bytes: u16 = @min(buffer.len, 1024);
            try cs.raw_write(
                1024,
                self.handshake.rand,
                &self.handshake.key_data,
                self.stream.writer(),
                [3]u8{ 0x17, 0x03, 0x03 },
                self.client_seq,
                buffer[0..curr_bytes],
            );
            self.client_seq += 1;
            return curr_bytes;
        }
    }
    unreachable;
}

pub fn close(self: *Connection) !void {
    inline for (ciphers.CipherSuites.all) |cs| {
        if (self.handshake.csuite == cs.tag) {
            try cs.raw_write(
                1024,
                self.handshake.rand,
                &self.handshake.key_data,
                self.stream.writer(),
                [3]u8{ 0x15, 0x03, 0x03 },
                self.client_seq,
                "\x01\x00",
            );
            self.client_seq += 1;
            return;
        }
    }
    unreachable;
}

pub fn deinit(self: *Connection) void {
    self.handshake.deinit();
}
