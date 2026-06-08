const std = @import("std");
const authon = @import("authon.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var auth = authon.Authon.init("your-app-id", "your-api-key");

    if (auth.connect()) |_| {
        try stdout.print("[+] Connected: {s} v{s}\n", .{ auth.app_name, auth.app_version });
    } else |err| {
        try stdout.print("[-] Connection failed: {}\n", .{err});
        return;
    }

    try stdout.print("\n[1] Login\n[2] License Key\n> ", .{});

    // Note: This is a minimal example showing SDK structure.
    // Full implementation in authon.zig handles HTTP via std.http.Client
    try stdout.print("[+] See authon.zig for full implementation\n", .{});
}
