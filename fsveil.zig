const std = @import("std");
const os = std.os;
const posix = std.posix;

const broker = @import("broker.zig");
const Ids = broker.Ids;
const MountOptions = broker.MountOptions;

pub const log_level: std.log.Level = .warn;

const zig_atleast_15 = @import("builtin").zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;

fn usage() !void {
    const str =
        \\fsveil: Runs the given program with a veiled view of the filesystem
        \\
        \\Usage: fsveil [OPTIONS...] FILES/DIRS -- CMD...
        \\
        \\Options:
        \\    --link TARGET LINK_NAME                   Create symlink LINK_NAME -> TARGET inside the veil
        \\    --bind-mount-host SRC DST                 Bind mount host directory SRC to DST
        \\    --tmpfs PATH                              Bind a writeable tmpfs to PATH
        \\    --start-mount-opt opt1,opt2,... DIRS...   Mount the following with the given mount options
        \\    --end-mount-opt                           End the previous --start-mount-opt
        \\    --keep-rw                                 Don't remount the veil as readonly
        \\    --tmp-sysroot PATH                        Override the default sysroot mount path (i.e. /mnt or /tmp)
        \\
    ;
    if (zig_atleast_15) {
        var stderr_writer = std.fs.File.stderr().writer(&.{});
        stderr_writer.interface.writeAll(str) catch return stderr_writer.err orelse error.Unexpected;
    } else {
        try std.io.getStdErr().writer().writeAll(str);
    }
}

var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);

fn getCmdlineOption(i: *usize) [*:0]u8 {
    i.* += 1;
    if (i.* >= os.argv.len) {
        std.log.err("command-line option '{s}' requires an argument", .{os.argv[i.* - 1]});
        posix.exit(0xff);
    }
    return os.argv[i.*];
}

pub fn main() !void {
    var mount_options_list = std.ArrayListUnmanaged(MountOptions){};
    var opt: struct {
        next_argv: ?[*:null]?[*:0]u8 = null,
        keep_readwrite: bool = false,
        tmp_sysroot: ?[:0]u8 = null,
    } = .{};

    var new_argc: usize = 1;
    {
        var arg_index: usize = 1;
        while (arg_index < os.argv.len) : (arg_index += 1) {
            const arg = std.mem.span(os.argv[arg_index]);
            if (std.mem.eql(u8, arg, "--")) {
                opt.next_argv = @ptrCast(os.argv[arg_index + 1 ..].ptr);
                break;
            } else if (std.mem.eql(u8, arg, "--link")) {
                os.argv[new_argc + 0] = arg.ptr;
                os.argv[new_argc + 1] = getCmdlineOption(&arg_index);
                os.argv[new_argc + 2] = getCmdlineOption(&arg_index);
                new_argc += 3;
            } else if (std.mem.eql(u8, arg, "--bind-mount-host")) {
                os.argv[new_argc + 0] = arg.ptr;
                os.argv[new_argc + 1] = getCmdlineOption(&arg_index);
                os.argv[new_argc + 2] = getCmdlineOption(&arg_index);
                new_argc += 3;
            } else if (std.mem.eql(u8, arg, "--tmpfs")) {
                os.argv[new_argc + 0] = arg.ptr;
                os.argv[new_argc + 1] = getCmdlineOption(&arg_index);
                new_argc += 2;
            } else if (std.mem.eql(u8, arg, "--keep-rw")) {
                opt.keep_readwrite = true;
            } else if (std.mem.eql(u8, arg, "--start-mount-opt")) {
                const cmdline_str = getCmdlineOption(&arg_index);
                try mount_options_list.append(arena.allocator(), MountOptions.init(cmdline_str, new_argc - 1));
            } else if (std.mem.eql(u8, arg, "--end-mount-opt")) {
                if (mount_options_list.items.len == 0) {
                    std.log.err("got --end-mount-opt without a corresponding --start-mount-opt", .{});
                    posix.exit(0xff);
                }
                mount_options_list.items[mount_options_list.items.len - 1].end = new_argc - 1;
            } else if (std.mem.eql(u8, arg, "--tmp-sysroot")) {
                opt.tmp_sysroot = std.mem.span(getCmdlineOption(&arg_index));
            } else {
                os.argv[new_argc] = arg.ptr;
                new_argc += 1;
            }
        }
    }

    if (new_argc <= 1) {
        try usage();
        posix.exit(0xff);
    }
    const next_argv = opt.next_argv orelse {
        std.log.err("missing '--' to delineate a command to execute", .{});
        posix.exit(0xff);
    };
    const next_program = next_argv[0] orelse {
        std.log.err("missing program after '--'", .{});
        posix.exit(0xff);
    };
    const sysroot_paths = os.argv[1..new_argc];
    const sysroot_path = opt.tmp_sysroot orelse pickSysrootMount(sysroot_paths);

    const pre_unshare_uids = getUids();
    std.log.info("PreUnshare Uids: {}", .{pre_unshare_uids});
    const pre_unshare_gids = getGids();
    std.log.info("PreUnshare Gids: {}", .{pre_unshare_gids});

    try unshare(.{
        .pre_unshare_uids = pre_unshare_uids,
        .pre_unshare_gids = pre_unshare_gids,
        .sysroot_paths = sysroot_paths,
        .mount_options_list = mount_options_list,
        .sysroot_path = sysroot_path,
        .keep_readwrite = opt.keep_readwrite,
    });

    {
        const uids = getUids();
        std.log.info("PostUnshare Uids: {}", .{uids});
    }

    // The broker already did chroot. chdir to restore working directory.
    var cwd_path_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const cwd_path = try std.process.getCwd(cwd_path_buf[0 .. cwd_path_buf.len - 1]);
    cwd_path_buf[cwd_path.len] = 0;
    std.log.info("cd '{s}'", .{cwd_path});
    try posix.chdirZ(@ptrCast(cwd_path));

    std.log.info("execve '{s}'", .{next_program});
    const errno = os.linux.execve(
        next_program,
        next_argv,
        @ptrCast(os.environ.ptr),
    );
    std.log.err("execve failed, errno={}", .{errno});
    posix.exit(0xff);
}

// Set up a new user + mount namespace with uid/gid maps, then set up the
// sysroot with all mount operations.
//
// On systems with AppArmor restricting unprivileged user namespaces (e.g.
// Ubuntu 24.04+), operations like writing uid/gid maps and mounting are
// blocked from inside the namespace. We fork a broker child BEFORE unshare;
// the broker stays outside the namespace and can perform privileged
// operations by entering the parent's namespaces via setns().
//
// Flow:
//   1. Create eventfd for synchronization
//   2. Fork broker child
//   --------------------------------------------------------------------------------
//     Parent 1. Unshare (NEWUSER|NEWNS)
//     Parent 2. Write to eventfd to signal unshare is complete
//     Parent 3. Wait for child to exit
//   --------------------------------------------------------------------------------
//     Broker 1. Wait on eventfd (meaning parent finished calling unshare)
//     Broker 2. Write id maps, enter parent's namespaces, do all mounts, exit.
fn unshare(args: broker.Args) !void {
    const event_fd: posix.fd_t = blk: {
        const rc = os.linux.eventfd(0, os.linux.EFD.CLOEXEC);
        break :blk switch (posix.errno(rc)) {
            .SUCCESS => @intCast(rc),
            else => |e| {
                std.log.err("eventfd failed, errno={}", .{e});
                posix.exit(0xff);
            },
        };
    };
    defer posix.close(event_fd);
    const parent_pid = os.linux.getpid();
    const broker_pid: posix.pid_t = blk: {
        const fork_rc = os.linux.fork();
        break :blk switch (posix.errno(fork_rc)) {
            .SUCCESS => @intCast(fork_rc),
            else => |e| {
                std.log.err("fork failed, errno={}", .{e});
                posix.exit(0xff);
            },
        };
    };
    if (broker_pid == 0) return broker.run(event_fd, parent_pid, &args);

    switch (posix.errno(os.linux.unshare(os.linux.CLONE.NEWUSER | os.linux.CLONE.NEWNS))) {
        .SUCCESS => {},
        else => |e| {
            std.log.err("unshare failed, errno={}", .{e});
            posix.exit(0xff);
        },
    }

    // signal broker that we've completed "unshare" by writing to the eventfd.
    {
        const n = posix.write(event_fd, std.mem.asBytes(&@as(u64, 1))) catch |err| {
            std.log.err("eventfd write failed: {s}", .{@errorName(err)});
            posix.exit(0xff);
        };
        if (n != @sizeOf(u64)) {
            std.log.err("eventfd write returned {} bytes, expected {}", .{ n, @sizeOf(u64) });
            posix.exit(0xff);
        }
    }

    const status = posix.waitpid(broker_pid, 0).status;
    if (posix.W.IFSIGNALED(status)) {
        std.log.err("broker killed by signal {}", .{posix.W.TERMSIG(status)});
        posix.exit(0xff);
    }
    if (!posix.W.IFEXITED(status)) {
        std.log.err("broker exited with unexpected status 0x{x}", .{status});
        posix.exit(0xff);
    }
    const exit_code = posix.W.EXITSTATUS(status);
    if (exit_code != 0) {
        std.log.err("broker exited with status {}", .{exit_code});
        posix.exit(exit_code);
    }
}

fn shell(name: []const u8) !void {
    var child = std.process.Child.init(&[_][]const u8{name}, std.heap.page_allocator);
    try child.spawn();
    const result = try child.wait();
    std.log.info("shell exited with {}", .{result});
    posix.exit(0);
}

//fn sysrootMountIsOk(sysroot_paths: []const [*:0]const u8, sysroot_path: []const u8) bool {
fn sysrootMountIsOk(sysroot_paths: anytype, sysroot_path: []const u8) bool {
    _ = sysroot_paths;
    _ = sysroot_path;
    //std.log.warn("TODO: implement sysrootMountIsOk", .{});
    return true;
}

// Find any directory where we can mount our sysroot. Picking a path closer to
// the root is nice because it will keep pathnames smaller, but, we don't want
// to mount over one of the file/directories we're going to be copying/mounting
// inside our sysroot.
//fn pickSysrootMount(sysroot_paths: []const [*:0]const u8) [:0]const u8 {
fn pickSysrootMount(sysroot_paths: anytype) [:0]const u8 {
    if (std.fs.accessAbsolute("/mnt", .{})) {
        if (sysrootMountIsOk(sysroot_paths, "/mnt")) return "/mnt";
    } else |_| {}
    if (std.fs.accessAbsolute("/tmp", .{})) {
        if (sysrootMountIsOk(sysroot_paths, "/tmp")) return "/tmp";
    } else |_| {}
    std.log.err("neither /mnt not /tmp can be used, TODO: maybe make a directory underneath /tmp?", .{});
    posix.exit(0xff);
}

fn getUids() Ids {
    var ids: Ids = undefined;
    switch (posix.errno(os.linux.getresuid(&ids.real, &ids.effective, &ids.saved))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("getresuid failed, errno={}", .{errno});
            posix.exit(0xff);
        },
    }
    return ids;
}

fn getGids() Ids {
    var ids: Ids = undefined;
    switch (posix.errno(os.linux.getresgid(&ids.real, &ids.effective, &ids.saved))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("getresgid failed, errno={}", .{errno});
            posix.exit(0xff);
        },
    }
    return ids;
}
