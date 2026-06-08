// ╔══════════════════════════════════════════════════════════════════════════════╗
// ║  Authon Zig SDK — Software Licensing & Authentication                      ║
// ║  Version: 1.0.0                                                            ║
// ║  Dependencies: std.http.Client (Zig stdlib)                                ║
// ║                                                                            ║
// ║  Website: https://authon.pro                                               ║
// ║  Docs:    https://authon.pro/docs                                          ║
// ║  Discord: https://discord.gg/jMZCTKPsmE                                    ║
// ║  Status:  https://authon.pro/status                                        ║
// ║  Health:  https://api.authon.pro/health                                    ║
// ║  GitHub:  https://github.com/authonpro                                     ║
// ║                                                                            ║
// ║  Requirements: Zig 0.12+ (std.http.Client)                                 ║
// ║                                                                            ║
// ║  Usage:                                                                    ║
// ║    const authon = @import("authon.zig");                                   ║
// ║    var client = authon.Client.init(allocator, "app-id", "api-key");        ║
// ║    defer client.deinit();                                                  ║
// ║    try client.appInit();                                                   ║
// ║    const session = try client.login("user", "pass", null);                 ║
// ╚══════════════════════════════════════════════════════════════════════════════╝

const std = @import("std");
const http = std.http;
const json = std.json;
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

/// SDK version string.
pub const version = "1.0.0";

/// Default Authon API endpoint.
pub const default_api_url = "https://api.authon.pro/v1";

/// Default HTTP request timeout (15 seconds).
pub const default_timeout_ns: u64 = 15 * std.time.ns_per_s;

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Errors that can occur when using the Authon SDK.
pub const AuthonError = error{
    /// API returned an error response.
    ApiError,
    /// Network or connection error.
    NetworkError,
    /// Failed to parse the API response.
    ParseError,
    /// Client is not in the expected state.
    StateError,
    /// Out of memory.
    OutOfMemory,
    /// HTTP connection failed.
    ConnectionFailed,
    /// Request timed out.
    Timeout,
};

// ═══════════════════════════════════════════════════════════════════════════════
// DATA TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Session data returned after successful authentication.
pub const SessionData = struct {
    session_token: []const u8,
    username: []const u8,
    level: i32,
    subscription: []const u8,
    expires_at: []const u8,
};

/// Application info from init().
pub const AppInfo = struct {
    name: []const u8,
    app_version: []const u8,
    hwid_lock: bool,
    hash_check: bool,
};

/// File entry from list_files.
pub const FileInfo = struct {
    id: []const u8,
    name: []const u8,
    size: i64,
    min_level: i32,
};

/// Online users data.
pub const OnlineData = struct {
    count: i32,
    users: []const []const u8,
};

/// Application statistics.
pub const StatsData = struct {
    total_users: i32,
    online_users: i32,
    total_keys: i32,
    app_version: []const u8,
};

/// Blacklist check result.
pub const BlacklistData = struct {
    blacklisted: bool,
    reason: ?[]const u8,
};

/// Referral redemption result.
pub const ReferralData = struct {
    expires_at: []const u8,
    reward_days: i32,
    message: []const u8,
};

/// Generic API response.
pub const Response = struct {
    success: bool,
    message: []const u8,
    raw_data: ?json.Value,

    pub fn getString(self: *const Response, key: []const u8) ?[]const u8 {
        if (self.raw_data) |data| {
            if (data == .object) {
                if (data.object.get(key)) |val| {
                    if (val == .string) return val.string;
                }
            }
        }
        return null;
    }

    pub fn getInt(self: *const Response, key: []const u8) i32 {
        if (self.raw_data) |data| {
            if (data == .object) {
                if (data.object.get(key)) |val| {
                    if (val == .integer) return @intCast(val.integer);
                }
            }
        }
        return 0;
    }

    pub fn getBool(self: *const Response, key: []const u8) bool {
        if (self.raw_data) |data| {
            if (data == .object) {
                if (data.object.get(key)) |val| {
                    if (val == .bool) return val.bool;
                }
            }
        }
        return false;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// CLIENT
// ═══════════════════════════════════════════════════════════════════════════════

/// Main Authon SDK client for Zig.
///
/// Provides methods for application initialization, user authentication,
/// session management, variable storage, file downloads, and activity logging.
///
/// Usage:
/// ```zig
/// var client = Client.init(allocator, "app-id", "api-key");
/// defer client.deinit();
/// try client.appInit();
/// const session = try client.login("user", "pass", null);
/// ```
pub const Client = struct {
    allocator: Allocator,
    app_id: []const u8,
    api_key: []const u8,
    api_url: []const u8,

    // Session state
    session_token: ?[]const u8 = null,
    username: ?[]const u8 = null,
    level: i32 = 0,
    subscription: ?[]const u8 = null,
    expires_at: ?[]const u8 = null,

    // App info
    app_name: ?[]const u8 = null,
    app_version: ?[]const u8 = null,
    hwid_lock: bool = false,
    hash_check: bool = false,
    initialized: bool = false,

    // Last error message
    last_error: []const u8 = "",

    /// Creates a new Authon client.
    ///
    /// Parameters:
    ///   allocator - Memory allocator for response data.
    ///   app_id    - Your Application ID from the Authon dashboard.
    ///   api_key   - Your API Key from the Authon dashboard.
    pub fn init(allocator: Allocator, app_id: []const u8, api_key: []const u8) Client {
        return .{
            .allocator = allocator,
            .app_id = app_id,
            .api_key = api_key,
            .api_url = default_api_url,
        };
    }

    /// Creates a new client with a custom API URL.
    pub fn initWithUrl(allocator: Allocator, app_id: []const u8, api_key: []const u8, api_url: []const u8) Client {
        return .{
            .allocator = allocator,
            .app_id = app_id,
            .api_key = api_key,
            .api_url = api_url,
        };
    }

    /// Cleans up client resources.
    pub fn deinit(self: *Client) void {
        _ = self;
        // Allocator handles memory cleanup
    }

    /// Returns true if the client has an active session.
    pub fn isAuthenticated(self: *const Client) bool {
        return self.session_token != null;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HWID GENERATION
    // ═══════════════════════════════════════════════════════════════════════════

    /// Generates a hardware ID unique to the current machine.
    ///
    /// Uses hostname and OS info, hashed with MD5 (via std.crypto).
    /// Returns a 32-character hex string.
    pub fn getHWID(allocator: Allocator) ![]const u8 {
        var raw_buf: [512]u8 = undefined;
        var raw_len: usize = 0;

        // Get hostname
        const hostname = std.posix.gethostname() catch "unknown";
        @memcpy(raw_buf[raw_len..][0..hostname.len], hostname);
        raw_len += hostname.len;

        // Add platform info
        const os_tag = @tagName(std.Target.current.os.tag);
        @memcpy(raw_buf[raw_len..][0..os_tag.len], os_tag);
        raw_len += os_tag.len;

        const arch_tag = @tagName(std.Target.current.cpu.arch);
        @memcpy(raw_buf[raw_len..][0..arch_tag.len], arch_tag);
        raw_len += arch_tag.len;

        // MD5 hash
        const Md5 = std.crypto.hash.Md5;
        var digest: [Md5.digest_length]u8 = undefined;
        Md5.hash(raw_buf[0..raw_len], &digest, .{});

        // Convert to hex string
        var hex_buf: [32]u8 = undefined;
        for (digest, 0..) |byte, i| {
            hex_buf[i * 2] = std.fmt.digitToChar(byte >> 4, .lower);
            hex_buf[i * 2 + 1] = std.fmt.digitToChar(byte & 0x0f, .lower);
        }

        return try allocator.dupe(u8, &hex_buf);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // INTERNAL HTTP
    // ═══════════════════════════════════════════════════════════════════════════

    /// Sends a POST request to the Authon API.
    fn request(self: *Client, payload_json: []const u8) !Response {
        var client = http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const uri = std.Uri.parse(self.api_url) catch return error.ParseError;

        var req = try client.open(.POST, uri, .{
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "User-Agent", .value = "Authon-Zig-SDK/" ++ version },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = payload_json.len };
        try req.send();
        try req.writeAll(payload_json);
        try req.finish();
        try req.wait();

        const body = try req.reader().readAllAlloc(self.allocator, 1024 * 1024);

        // Parse JSON response
        var parsed = try json.parseFromSlice(json.Value, self.allocator, body, .{});
        defer parsed.deinit();

        const root = parsed.value;
        const success = if (root.object.get("success")) |v| v == .bool and v.bool else false;
        const message = if (root.object.get("message")) |v| (if (v == .string) v.string else "") else "";

        const data_val = root.object.get("data");

        return Response{
            .success = success,
            .message = try self.allocator.dupe(u8, message),
            .raw_data = data_val,
        };
    }

    /// Builds a JSON payload string.
    fn buildPayload(self: *Client, fields: anytype) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        var writer = buf.writer();

        try writer.writeAll("{");
        try writer.print("\"appId\":\"{s}\",\"apiKey\":\"{s}\"", .{ self.app_id, self.api_key });

        inline for (std.meta.fields(@TypeOf(fields))) |field| {
            const value = @field(fields, field.name);
            if (@TypeOf(value) == ?[]const u8) {
                if (value) |v| {
                    try writer.print(",\"{s}\":\"{s}\"", .{ field.name, v });
                }
            } else {
                try writer.print(",\"{s}\":\"{s}\"", .{ field.name, value });
            }
        }

        try writer.writeAll("}");
        return buf.toOwnedSlice();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════════

    /// Initializes the connection to the Authon API.
    /// Must be called before any other API method.
    ///
    /// On success, sets app_name, app_version, hwid_lock, hash_check.
    pub fn appInit(self: *Client) !AppInfo {
        const payload = try self.buildPayload(.{ .type = "init" });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);

        if (!resp.success) {
            self.last_error = resp.message;
            return error.ApiError;
        }

        const info = AppInfo{
            .name = resp.getString("name") orelse "",
            .app_version = resp.getString("version") orelse "",
            .hwid_lock = resp.getBool("hwidLock"),
            .hash_check = resp.getBool("hashCheck"),
        };

        self.app_name = info.name;
        self.app_version = info.app_version;
        self.hwid_lock = info.hwid_lock;
        self.hash_check = info.hash_check;
        self.initialized = true;

        return info;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // AUTHENTICATION
    // ═══════════════════════════════════════════════════════════════════════════

    /// Authenticates with username and password.
    ///
    /// Parameters:
    ///   username - User's username.
    ///   password - User's password.
    ///   hwid     - Hardware ID (null to auto-generate).
    ///
    /// Returns SessionData on success.
    /// Possible errors: "Invalid credentials", "Account banned",
    /// "Hardware ID mismatch", "Subscription expired"
    pub fn login(self: *Client, username: []const u8, password: []const u8, hwid: ?[]const u8) !SessionData {
        if (username.len == 0 or password.len == 0) {
            self.last_error = "Username and password are required";
            return error.StateError;
        }

        const hw = hwid orelse try getHWID(self.allocator);

        const payload = try self.buildPayload(.{
            .type = "login",
            .username = username,
            .password = password,
            .hwid = hw,
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);

        if (!resp.success) {
            self.last_error = resp.message;
            return error.ApiError;
        }

        const session = SessionData{
            .session_token = resp.getString("sessionToken") orelse "",
            .username = resp.getString("username") orelse "",
            .level = resp.getInt("level"),
            .subscription = resp.getString("subscription") orelse "",
            .expires_at = resp.getString("expiresAt") orelse "",
        };

        self.session_token = session.session_token;
        self.username = session.username;
        self.level = session.level;
        self.subscription = session.subscription;
        self.expires_at = session.expires_at;

        return session;
    }

    /// Authenticates using a license key only.
    pub fn license(self: *Client, license_key: []const u8, hwid: ?[]const u8) !SessionData {
        if (license_key.len == 0) {
            self.last_error = "License key is required";
            return error.StateError;
        }

        const hw = hwid orelse try getHWID(self.allocator);

        const payload = try self.buildPayload(.{
            .type = "license",
            .licenseKey = license_key,
            .hwid = hw,
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);

        if (!resp.success) {
            self.last_error = resp.message;
            return error.ApiError;
        }

        const session = SessionData{
            .session_token = resp.getString("sessionToken") orelse "",
            .username = resp.getString("username") orelse "",
            .level = resp.getInt("level"),
            .subscription = resp.getString("subscription") orelse "",
            .expires_at = resp.getString("expiresAt") orelse "",
        };

        self.session_token = session.session_token;
        self.username = session.username;
        self.level = session.level;
        self.subscription = session.subscription;
        self.expires_at = session.expires_at;

        return session;
    }

    /// Registers a new user account with a license key.
    pub fn register(self: *Client, username: []const u8, password: []const u8, license_key: []const u8, hwid: ?[]const u8) !void {
        if (username.len == 0 or password.len == 0 or license_key.len == 0) {
            self.last_error = "Username, password, and licenseKey are required";
            return error.StateError;
        }

        const hw = hwid orelse try getHWID(self.allocator);

        const payload = try self.buildPayload(.{
            .type = "register",
            .username = username,
            .password = password,
            .licenseKey = license_key,
            .hwid = hw,
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);

        if (!resp.success) {
            self.last_error = resp.message;
            return error.ApiError;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SESSION MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /// Validates the current session (heartbeat).
    pub fn check(self: *Client) !bool {
        const token = self.session_token orelse return false;

        const payload = try self.buildPayload(.{
            .type = "check",
            .sessionToken = token,
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);
        return resp.success;
    }

    /// Ends the current session and clears local state.
    pub fn logout(self: *Client) !void {
        const token = self.session_token orelse return;

        const payload = try self.buildPayload(.{
            .type = "logout",
            .sessionToken = token,
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);

        if (resp.success) {
            self.session_token = null;
            self.username = null;
            self.level = 0;
            self.subscription = null;
            self.expires_at = null;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VARIABLES
    // ═══════════════════════════════════════════════════════════════════════════

    /// Gets an application-level variable.
    pub fn getVar(self: *Client, key: []const u8) !?[]const u8 {
        const payload = try self.buildPayload(.{
            .type = "var",
            .key = key,
            .sessionToken = self.session_token orelse "",
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);
        if (!resp.success) return null;
        return resp.getString("value");
    }

    /// Sets a user-level variable.
    pub fn setVar(self: *Client, key: []const u8, value: []const u8) !void {
        const token = self.session_token orelse return error.StateError;

        const payload = try self.buildPayload(.{
            .type = "setvar",
            .key = key,
            .value = value,
            .sessionToken = token,
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);
        if (!resp.success) {
            self.last_error = resp.message;
            return error.ApiError;
        }
    }

    /// Gets a user-level variable.
    pub fn getUserVar(self: *Client, key: []const u8) !?[]const u8 {
        const token = self.session_token orelse return error.StateError;

        const payload = try self.buildPayload(.{
            .type = "getvar",
            .key = key,
            .sessionToken = token,
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);
        if (!resp.success) return null;
        return resp.getString("value");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FILES
    // ═══════════════════════════════════════════════════════════════════════════

    /// Lists files available to the authenticated user.
    pub fn listFiles(self: *Client) !Response {
        const token = self.session_token orelse return error.StateError;

        const payload = try self.buildPayload(.{
            .type = "list_files",
            .sessionToken = token,
        });
        defer self.allocator.free(payload);

        return try self.request(payload);
    }

    /// Downloads a file by ID. Returns raw bytes.
    pub fn downloadFile(self: *Client, file_id: []const u8) ![]const u8 {
        const token = self.session_token orelse return error.StateError;
        if (file_id.len == 0) return error.StateError;

        const payload = try self.buildPayload(.{
            .type = "file",
            .fileId = file_id,
            .sessionToken = token,
        });
        defer self.allocator.free(payload);

        // For binary downloads, we use the raw HTTP client
        var client = http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const uri = std.Uri.parse(self.api_url) catch return error.ParseError;

        var req = try client.open(.POST, uri, .{
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = payload.len };
        try req.send();
        try req.writeAll(payload);
        try req.finish();
        try req.wait();

        return try req.reader().readAllAlloc(self.allocator, 100 * 1024 * 1024);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LOGGING & ANALYTICS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Sends an activity log message to the dashboard.
    pub fn log(self: *Client, message: []const u8) !void {
        const msg = if (message.len > 500) message[0..500] else message;

        const payload = try self.buildPayload(.{
            .type = "log",
            .message = msg,
            .sessionToken = self.session_token orelse "",
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);
        if (!resp.success) {
            self.last_error = resp.message;
            return error.ApiError;
        }
    }

    /// Gets the list of currently online users.
    pub fn fetchOnline(self: *Client) !Response {
        const token = self.session_token orelse return error.StateError;

        const payload = try self.buildPayload(.{
            .type = "fetch_online",
            .sessionToken = token,
        });
        defer self.allocator.free(payload);

        return try self.request(payload);
    }

    /// Gets application statistics.
    pub fn fetchStats(self: *Client) !Response {
        const token = self.session_token orelse return error.StateError;

        const payload = try self.buildPayload(.{
            .type = "fetch_stats",
            .sessionToken = token,
        });
        defer self.allocator.free(payload);

        return try self.request(payload);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECURITY
    // ═══════════════════════════════════════════════════════════════════════════

    /// Checks if an IP or HWID is blacklisted.
    pub fn checkBlacklist(self: *Client, ip: ?[]const u8, hwid: ?[]const u8) !BlacklistData {
        var buf = std.ArrayList(u8).init(self.allocator);
        var writer = buf.writer();
        defer buf.deinit();

        try writer.print("{{\"type\":\"check_blacklist\",\"appId\":\"{s}\",\"apiKey\":\"{s}\"", .{ self.app_id, self.api_key });
        if (ip) |v| try writer.print(",\"ip\":\"{s}\"", .{v});
        if (hwid) |v| try writer.print(",\"hwid\":\"{s}\"", .{v});
        try writer.writeAll("}");

        const payload = try buf.toOwnedSlice();
        defer self.allocator.free(payload);

        const resp = try self.request(payload);
        if (!resp.success) {
            self.last_error = resp.message;
            return error.ApiError;
        }

        return BlacklistData{
            .blacklisted = resp.getBool("blacklisted"),
            .reason = resp.getString("reason"),
        };
    }

    /// Redeems a referral code for bonus subscription days.
    pub fn redeemReferral(self: *Client, code: []const u8) !ReferralData {
        const token = self.session_token orelse return error.StateError;
        if (code.len == 0) return error.StateError;

        const payload = try self.buildPayload(.{
            .type = "redeem_referral",
            .code = code,
            .sessionToken = token,
        });
        defer self.allocator.free(payload);

        const resp = try self.request(payload);
        if (!resp.success) {
            self.last_error = resp.message;
            return error.ApiError;
        }

        return ReferralData{
            .expires_at = resp.getString("expiresAt") orelse "",
            .reward_days = resp.getInt("rewardDays"),
            .message = resp.message,
        };
    }
};
