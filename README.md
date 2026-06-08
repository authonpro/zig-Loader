# Authon Zig SDK

<p align="center">
  <img src="https://authon.pro/logo.png" alt="Authon" width="80" />
  <br/>
  <strong>Official Zig SDK for Authon — Software Licensing & Authentication Platform</strong>
</p>

<p align="center">
  <a href="https://authon.pro">Website</a> •
  <a href="https://authon.pro/docs">Docs</a> •
  <a href="https://discord.gg/jMZCTKPsmE">Discord</a> •
  <a href="https://authon.pro/status">Status</a>
</p>

---

## Requirements

- Zig 0.12+
- No external dependencies (stdlib only)

## Installation

Copy `authon.zig` into your project's `src/` directory.

## Quick Start

```zig
const authon = @import("authon.zig");

pub fn main() !void {
    var auth = authon.Authon.init("your-app-id", "your-api-key");
    try auth.connect();
    try auth.login("username", "password");
    std.debug.print("Level: {d}\n", .{auth.level});
    auth.logout();
}
```

## Build & Run

```bash
zig build-exe src/example.zig
./example
```

## Links

- 🌐 Website: https://authon.pro
- 📖 Docs: https://authon.pro/docs
- 💬 Discord: https://discord.gg/jMZCTKPsmE
- 📊 Status: https://authon.pro/status

## License

MIT
