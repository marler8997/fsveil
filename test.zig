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
    cwd: ?[]const u8 = null,
}) !Result {
    // absolute so it still resolves when cwd is set
    const exe = try std.Io.Dir.cwd().realPathFileAlloc(testing.io, fsveil_exe, testing.allocator);
    defer testing.allocator.free(exe);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    try argv.append(testing.allocator, exe);
    try argv.appendSlice(testing.allocator, args);
    const result = try std.process.run(testing.allocator, testing.io, .{
        .argv = argv.items,
        .environ_map = options.environ_map,
        .cwd = if (options.cwd) |cwd| .{ .path = cwd } else .inherit,
    });
    return .{ .term = result.term, .stdout = result.stdout, .stderr = result.stderr };
}

/// Runs a shell script in a veil with enough of the host to run /bin/sh.
fn runScript(script: []const u8, options: struct {
    /// fsveil args after the ones needed to run /bin/sh
    veil_args: []const []const u8 = &.{},
    script_args: []const []const u8 = &.{},
    environ_map: ?*const std.process.Environ.Map = null,
    cwd: ?[]const u8 = null,
}) !Result {
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(testing.allocator);
    try args.appendSlice(testing.allocator, &.{ "/usr", "/bin", "/lib" });
    // /bin/sh's dynamic loader lives here on x86_64 but it doesn't exist on aarch64
    if (std.Io.Dir.accessAbsolute(testing.io, "/lib64", .{})) {
        try args.append(testing.allocator, "/lib64");
    } else |_| {}
    try args.appendSlice(testing.allocator, options.veil_args);
    try args.appendSlice(testing.allocator, &.{ "--", "/bin/sh", "-c", script });
    try args.appendSlice(testing.allocator, options.script_args);
    return run(args.items, .{ .environ_map = options.environ_map, .cwd = options.cwd });
}

fn expectExit(result: Result, code: u8) !void {
    errdefer result.dump();
    try testing.expectEqual(std.process.Child.Term{ .exited = code }, result.term);
}

fn expectStdout(result: Result, expected: []const u8) !void {
    try expectExit(result, 0);
    errdefer result.dump();
    try testing.expectEqualStrings(expected, result.stdout);
}

/// A temporary directory containing file.txt.
const TmpDir = struct {
    tmp: testing.TmpDir,
    path_buf: [std.Io.Dir.max_path_bytes]u8,
    path_len: usize,

    fn init(self: *TmpDir) !void {
        self.tmp = testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        try self.tmp.dir.writeFile(testing.io, .{ .sub_path = "file.txt", .data = "file content\n" });
        self.path_len = try self.tmp.dir.realPath(testing.io, &self.path_buf);
    }
    fn deinit(self: *TmpDir) void {
        self.tmp.cleanup();
    }
    fn path(self: *const TmpDir) []const u8 {
        return self.path_buf[0..self.path_len];
    }
    fn print(self: *const TmpDir, comptime fmt: []const u8, args: anytype) ![]u8 {
        _ = self;
        return std.fmt.allocPrint(testing.allocator, fmt, args);
    }
};

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

test "the veil only contains what was asked for" {
    var tmp: TmpDir = undefined;
    try tmp.init();
    defer tmp.deinit();
    const file_path = try tmp.print("{s}/file.txt", .{tmp.path()});
    defer testing.allocator.free(file_path);
    const result = try runScript(
        \\test -e /etc/passwd && echo host /etc/passwd is visible
        \\readlink /opt/env
        \\cat /src/file.txt
        \\cat "$0"
        \\touch /scratch/x && echo /scratch is writable
        \\touch /x 2>/dev/null || echo / is readonly
    , .{
        .veil_args = &.{ "--link", "/usr/bin/env", "/opt/env", "--tmpfs", "/scratch", "--bind-mount-host", tmp.path(), "/src", file_path },
        .script_args = &.{file_path},
    });
    defer result.deinit();
    try expectStdout(result,
        \\/usr/bin/env
        \\file content
        \\file content
        \\/scratch is writable
        \\/ is readonly
        \\
    );
}

test "--keep-rw leaves the veil root writable" {
    const result = try runScript("touch /x && echo / is writable", .{ .veil_args = &.{"--keep-rw"} });
    defer result.deinit();
    try expectStdout(result, "/ is writable\n");
}

test "relative paths are relative to the cwd" {
    var tmp: TmpDir = undefined;
    try tmp.init();
    defer tmp.deinit();
    {
        const result = try runScript("cat file.txt", .{ .veil_args = &.{"file.txt"}, .cwd = tmp.path() });
        defer result.deinit();
        try expectStdout(result, "file content\n");
    }
    {
        const result = try runScript("pwd; cat file.txt", .{ .veil_args = &.{"."}, .cwd = tmp.path() });
        defer result.deinit();
        const expected = try tmp.print("{s}\nfile content\n", .{tmp.path()});
        defer testing.allocator.free(expected);
        try expectStdout(result, expected);
    }
}

test "a successful veil only prints the command's output" {
    const result = try runScript("echo hello", .{});
    defer result.deinit();
    try expectStdout(result, "hello\n");
    errdefer result.dump();
    try testing.expectEqualStrings("", result.stderr);
}

test "--start-mount-opt applies to bind mounts and tmpfs" {
    var tmp: TmpDir = undefined;
    try tmp.init();
    defer tmp.deinit();
    // prints which of nosuid/nodev/noexec each mount has
    const result = try runScript(
        \\for m in "$0" /scratch /plain; do
        \\  printf '%s:' "$m"
        \\  while read -r dev mnt type opts rest; do
        \\    [ "$mnt" = "$m" ] || continue
        \\    case ",$opts," in *,nosuid,*) printf ' nosuid' ;; esac
        \\    case ",$opts," in *,nodev,*) printf ' nodev' ;; esac
        \\    case ",$opts," in *,noexec,*) printf ' noexec' ;; esac
        \\  done < /proc/self/mounts
        \\  echo
        \\done
    , .{
        .veil_args = &.{
            // the options tupleapp uses
            "--start-mount-opt", "nosuid,nodev,noexec,private,recursive", "/dev",     "/proc",   "--end-mount-opt",
            "--start-mount-opt", "nosuid,nodev,noexec",                   tmp.path(), "--tmpfs", "/scratch",
            "--end-mount-opt",   "--tmpfs",                               "/plain",
        },
        .script_args = &.{tmp.path()},
    });
    defer result.deinit();
    const expected = try tmp.print("{s}: nosuid nodev noexec\n/scratch: nosuid nodev noexec\n/plain:\n", .{tmp.path()});
    defer testing.allocator.free(expected);
    try expectStdout(result, expected);
}
