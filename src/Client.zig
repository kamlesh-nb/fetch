const std = @import("std");
const Connection = @import("Connection.zig");

pub const Protocol = enum(u8) {
    plain,
    tls,
};

const Client = @This();

allocator: std.mem.Allocator,
protocol: Protocol,
hostname: []const u8,
port: u16,
connection: Connection = undefined,

pub const Reader = std.io.Reader(*@This(), Connection.ReaderError, read);
pub const Writer = std.io.Writer(*@This(), std.net.Stream.WriteError, write);


pub fn connect(self: *Client) !void {
     const stream = try std.net.tcpConnectToHost(self.allocator, self.hostname, self.port);
    if(self.protocol == .tls) {
        self.connection = try Connection.init(self.allocator, stream, self.hostname, true);
    } else {
        self.connection = try Connection.init(self.allocator, stream, self.hostname, false);
    }
}

pub fn reader(self: *Client) Reader {
    return .{ .context = self };
}

pub fn writer(self: *Client) Writer {
    return .{ .context = self };
}

pub fn read(self: *Client, buffer: []u8) !usize {
    return try self.connection.read(buffer);
}

pub fn write(self: *Client, buffer: []const u8) !usize {
    return try self.connection.write(buffer);
}

pub fn close(self: *Client) !void {
    if(self.protocol == .tls) try self.connection.close();
    return;
}

pub fn deinit(self: *Client) void {
    self.connection.deinit();
}