//! Runs the fsveil executable, needs a linux host that allows unprivileged
//! user namespaces.

const std = @import("std");
const testing = std.testing;
const fsveil_exe = @import("build_options").fsveil;

const Result = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn deinit(r: Result) void {
        testing.allocator.free(r.stdout);
        testing.allocator.free(r.stderr);
    }

    fn dump(r: Result) void {
        std.debug.print("--- fsveil {}\n--- stdout:\n{s}--- stderr:\n{s}---\n", .{ r.term, r.stdout, r.stderr });
    }
};

/// Runs fsveil with the given args.
fn run(args: []const []const u8, options: struct {
    environ_map: ?*const std.process.Environ.Map = null,
}) !Result {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    try argv.append(testing.allocator, fsveil_exe);
    try argv.appendSlice(testing.allocator, args);
    const result = try std.process.run(testing.allocator, testing.io, .{
        .argv = argv.items,
        .environ_map = options.environ_map,
    });
    return .{ .term = result.term, .stdout = result.stdout, .stderr = result.stderr };
}

/// Runs a shell script in a veil with enough of the host to run /bin/sh.
fn runScript(script: []const u8, options: struct {
    script_args: []const []const u8 = &.{},
    environ_map: ?*const std.process.Environ.Map = null,
}) !Result {
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(testing.allocator);
    try args.appendSlice(testing.allocator, &.{ "/usr", "/bin", "/lib" });
    // /bin/sh's dynamic loader lives here on x86_64 but it doesn't exist on aarch64
    if (std.Io.Dir.accessAbsolute(testing.io, "/lib64", .{})) {
        try args.append(testing.allocator, "/lib64");
    } else |_| {}
    try args.appendSlice(testing.allocator, &.{ "--", "/bin/sh", "-c", script });
    try args.appendSlice(testing.allocator, options.script_args);
    return run(args.items, .{ .environ_map = options.environ_map });
}

fn expectExit(result: Result, code: u8) !void {
    errdefer result.dump();
    try testing.expectEqual(std.process.Child.Term{ .exited = code }, result.term);
}

test "runs the command with its args and environment" {
    var environ_map: std.process.Environ.Map = .init(testing.allocator);
    defer environ_map.deinit();
    try environ_map.put("FSVEIL_TEST", "from the environment");
    const result = try runScript("echo \"$0|$1|$FSVEIL_TEST\"", .{
        .script_args = &.{ "arg zero", "arg one" },
        .environ_map = &environ_map,
    });
    defer result.deinit();
    try expectExit(result, 0);
    try testing.expectEqualStrings("arg zero|arg one|from the environment\n", result.stdout);
}

test "exits with the command's exit code" {
    const result = try runScript("exit 7", .{});
    defer result.deinit();
    try expectExit(result, 7);
}

test "command-line errors" {
    const cases = [_]struct { args: []const []const u8, stderr: []const u8 }{
        .{ .args = &.{}, .stderr = "Usage: fsveil [OPTIONS...] FILES/DIRS -- CMD..." },
        .{ .args = &.{ "--keep-rw", "--", "/bin/true" }, .stderr = "Usage: fsveil [OPTIONS...] FILES/DIRS -- CMD..." },
        .{ .args = &.{"/usr"}, .stderr = "error: missing '--' to delineate a command to execute\n" },
        .{ .args = &.{ "/usr", "--" }, .stderr = "error: missing program after '--'\n" },
        .{ .args = &.{ "/usr", "--tmpfs" }, .stderr = "error: command-line option '--tmpfs' requires an argument\n" },
        .{ .args = &.{ "--tmpfs", "--", "/bin/true" }, .stderr = "error: command-line option '--tmpfs' requires an argument\n" },
        .{ .args = &.{ "/usr", "--link", "/a" }, .stderr = "error: command-line option '--link' requires an argument\n" },
        .{ .args = &.{ "--start-mount-opt", "bogus", "/usr", "--", "/bin/true" }, .stderr = "error: unknown mount option 'bogus'\n" },
        .{ .args = &.{ "/usr", "--end-mount-opt", "--", "/bin/true" }, .stderr = "error: got --end-mount-opt without a corresponding --start-mount-opt\n" },
        .{
            .args = &.{ "--start-mount-opt", "nosuid", "--start-mount-opt", "nodev", "/usr", "--end-mount-opt", "--", "/bin/true" },
            .stderr = "error: got --start-mount-opt before the --end-mount-opt of the previous one\n",
        },
    };
    for (cases) |case| {
        const result = try run(case.args, .{});
        defer result.deinit();
        errdefer std.debug.print("args: {f}\n", .{std.json.fmt(case.args, .{})});
        try expectExit(result, 0xff);
        if (std.mem.indexOf(u8, result.stderr, case.stderr) == null) {
            result.dump();
            std.debug.print("expected stderr to contain: {s}\n", .{case.stderr});
            return error.TestUnexpectedStderr;
        }
    }
}

test "a path that doesn't exist is an error" {
    const result = try run(&.{ "/usr", "/fsveil-test-does-not-exist", "--", "/bin/true" }, .{});
    defer result.deinit();
    try expectExit(result, 0xff);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "'/fsveil-test-does-not-exist'") != null);
}
