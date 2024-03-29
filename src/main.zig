pub const Client = @import("Client.zig");

const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const deinit_status = gpa.deinit();
        if (deinit_status == .leak) std.testing.expect(false) catch @panic("TEST FAIL");
    }
    const allocator = gpa.allocator();

    const host = "jsonplaceholder.typicode.com";

    const port: u16 = 443;

    var cli = Client{ .allocator = allocator, .hostname = host, .port = port, .protocol = .tls };
    defer cli.deinit();
    try cli.connect();
    _ = try cli.writer().write("buffer: []const u8");

    var buffer: [1024]u8 = undefined;
    const len = try cli.read(buffer[0..1024]);

    std.debug.print("\nResponse: \n{s}\n", .{buffer[0..len]});
}
