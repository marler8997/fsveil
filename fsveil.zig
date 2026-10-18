const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

const veil = @import("veil.zig");
const Ids = veil.Ids;

pub const std_options: std.Options = .{
    .log_level = .warn,
    // see build.zig, staticio only compiles the Io operations fsveil reaches
    .io_vtable = .threaded,
    // The default 256 KiB signal stack is threadlocal, zeroing it at startup
    // was most of fsveil's runtime. zig 0.15 had no signal stack.
    .signal_stack_size = null,
};

fn usage(io: Io) Io.File.Writer.Error!void {
    try Io.File.stderr().writeStreamingAll(io,
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
    );
}

pub fn main(init: std.process.Init.Minimal) !void {
    // fsveil never uses async/concurrent Io so it doesn't need a gpa. Taking
    // Init.Minimal instead of Init also avoids parsing the environment into a
    // map we'd never use.
    var threaded: std.Io.Threaded = .init(.failing, .{ .environ = init.environ });
    const io = threaded.io();

    const all_args = init.args.vector[1..];
    const dash_index = for (all_args, 0..) |arg, i| {
        if (std.mem.eql(u8, std.mem.span(arg), "--")) break i;
    } else null;
    const veil_args = all_args[0 .. dash_index orelse all_args.len];

    // validate the veil args, setupSysroot iterates them again to do the work
    var opt: struct {
        keep_readwrite: bool = false,
        tmp_sysroot: ?[:0]const u8 = null,
    } = .{};
    {
        var entry_count: usize = 0;
        var mount_opt_active = false;
        var arg_it: veil.ArgIterator = .{ .args = veil_args };
        while (arg_it.next()) |arg| switch (arg) {
            .path, .link, .bind_mount_host, .tmpfs => entry_count += 1,
            .start_mount_opt => {
                if (mount_opt_active) {
                    std.log.err("got --start-mount-opt before the --end-mount-opt of the previous one", .{});
                    std.process.exit(0xff);
                }
                mount_opt_active = true;
            },
            .end_mount_opt => {
                if (!mount_opt_active) {
                    std.log.err("got --end-mount-opt without a corresponding --start-mount-opt", .{});
                    std.process.exit(0xff);
                }
                mount_opt_active = false;
            },
            .keep_rw => opt.keep_readwrite = true,
            .tmp_sysroot => |path| opt.tmp_sysroot = std.mem.span(path),
        };
        if (entry_count == 0) {
            try usage(io);
            std.process.exit(0xff);
        }
    }

    const next_argv: [*:null]const ?[*:0]const u8 = if (dash_index) |i| @ptrCast(all_args[i + 1 ..].ptr) else {
        std.log.err("missing '--' to delineate a command to execute", .{});
        std.process.exit(0xff);
    };
    const next_program = next_argv[0] orelse {
        std.log.err("missing program after '--'", .{});
        std.process.exit(0xff);
    };
    const sysroot_path = opt.tmp_sysroot orelse pickSysrootMount(io, veil_args);

    const pre_unshare_uids = getUids();
    std.log.info("PreUnshare Uids: {}", .{pre_unshare_uids});
    const pre_unshare_gids = getGids();
    std.log.info("PreUnshare Gids: {}", .{pre_unshare_gids});

    var cwd_path_buf: [Io.Dir.max_path_bytes + 1]u8 = undefined;
    const cwd_path_len = try std.process.currentPath(io, cwd_path_buf[0 .. cwd_path_buf.len - 1]);
    cwd_path_buf[cwd_path_len] = 0;
    const cwd_path = cwd_path_buf[0..cwd_path_len :0];

    veil.enterNewNamespaces(pre_unshare_uids, pre_unshare_gids);
    {
        const uids = getUids();
        std.log.info("PostUnshare Uids: {}", .{uids});
    }

    // entering the mount namespace moved us to its root directory, go back so
    // relative veil paths resolve against the cwd fsveil was started in
    chdirOrExit(cwd_path);
    veil.setupSysroot(io, veil_args, sysroot_path, opt.keep_readwrite) catch |err| {
        std.log.err("setupSysroot failed: {s}", .{@errorName(err)});
        std.process.exit(0xff);
    };
    // setupSysroot chroots into the sysroot, cwd is still outside of it
    chdirOrExit(cwd_path);

    std.log.info("execve '{s}'", .{next_program});
    const errno = linux.execve(
        next_program,
        next_argv,
        init.environ.block.slice.ptr,
    );
    std.log.err("execve failed, errno={}", .{linux.errno(errno)});
    std.process.exit(0xff);
}

fn chdirOrExit(path: [:0]const u8) void {
    std.log.info("cd '{s}'", .{path});
    switch (linux.errno(linux.chdir(path))) {
        .SUCCESS => {},
        else => |e| {
            std.log.err("chdir '{s}' failed, errno={}", .{ path, e });
            std.process.exit(0xff);
        },
    }
}

fn sysrootMountIsOk(veil_args: []const [*:0]const u8, sysroot_path: []const u8) bool {
    _ = veil_args;
    _ = sysroot_path;
    //std.log.warn("TODO: implement sysrootMountIsOk", .{});
    return true;
}

// Find any directory where we can mount our sysroot. Picking a path closer to
// the root is nice because it will keep pathnames smaller, but, we don't want
// to mount over one of the file/directories we're going to be copying/mounting
// inside our sysroot.
fn pickSysrootMount(io: Io, veil_args: []const [*:0]const u8) [:0]const u8 {
    if (Io.Dir.accessAbsolute(io, "/mnt", .{})) {
        if (sysrootMountIsOk(veil_args, "/mnt")) return "/mnt";
    } else |_| {}
    if (Io.Dir.accessAbsolute(io, "/tmp", .{})) {
        if (sysrootMountIsOk(veil_args, "/tmp")) return "/tmp";
    } else |_| {}
    std.log.err("neither /mnt not /tmp can be used, TODO: maybe make a directory underneath /tmp?", .{});
    std.process.exit(0xff);
}

fn getUids() Ids {
    var ids: Ids = undefined;
    switch (linux.errno(linux.getresuid(&ids.real, &ids.effective, &ids.saved))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("getresuid failed, errno={}", .{errno});
            std.process.exit(0xff);
        },
    }
    return ids;
}

fn getGids() Ids {
    var ids: Ids = undefined;
    switch (linux.errno(linux.getresgid(&ids.real, &ids.effective, &ids.saved))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("getresgid failed, errno={}", .{errno});
            std.process.exit(0xff);
        },
    }
    return ids;
}
