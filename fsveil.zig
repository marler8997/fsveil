const std = @import("std");
const os = std.os;
const posix = std.posix;

pub const log_level: std.log.Level = .warn;

fn usage() !void {
    try std.io.getStdErr().writer().writeAll(
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

    // NEWPID might be necessary for mounting /proc in some cases
    switch (posix.errno(os.linux.unshare(os.linux.CLONE.NEWUSER | os.linux.CLONE.NEWNS))) {
        .SUCCESS => {},
        else => |e| {
            std.log.err("unshare failed, errno={}", .{e});
            posix.exit(0xff);
        },
    }
    {
        const uids = getUids();
        std.log.info("PostUnshare Uids: {}", .{uids});
    }
    {
        const fd = try posix.open("/proc/self/uid_map", .{ .ACCMODE = .WRONLY }, 0);
        defer posix.close(fd);
        var buf: [200]u8 = undefined;
        const content = try std.fmt.bufPrint(&buf, "{} {0} 1", .{pre_unshare_uids.real});
        const written = try posix.write(fd, content);
        std.debug.assert(written == content.len);
    }
    {
        const uids = getUids();
        std.log.info("PostSetUidMap Uids: {}", .{uids});
    }
    {
        const fd = try posix.open("/proc/self/gid_map", .{ .ACCMODE = .WRONLY }, 0);
        defer posix.close(fd);
        var buf: [200]u8 = undefined;
        const content = try std.fmt.bufPrint(&buf, "0 {} 1", .{pre_unshare_gids.real});
        const written = try posix.write(fd, content);
        std.debug.assert(written == content.len);
    }
    {
        const fd = posix.open("/proc/self/setgroups", .{ .ACCMODE = .WRONLY }, 0) catch |err| @panic(@errorName(err));
        defer posix.close(fd);
        const content = "deny";
        const written = try posix.write(fd, content);
        std.debug.assert(written == content.len);
    }

    std.log.info("marking all mounts as private", .{});
    switch (posix.errno(os.linux.mount("none", "/", null, os.linux.MS.REC | os.linux.MS.PRIVATE, 0))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("mount failed with E{s}", .{@tagName(errno)});
            posix.exit(0xff);
        },
    }

    std.log.info("mounting the new sysroot as a tmpfs to '{s}'", .{sysroot_path});
    switch (posix.errno(os.linux.mount("none", sysroot_path, "tmpfs", 0, 0))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("mount failed with E{s}", .{@tagName(errno)});
            posix.exit(0xff);
        },
    }

    //try shell("sh");
    var mount_option_index: usize = 0;

    var path_index: usize = 0;
    while (path_index < sysroot_paths.len) : (path_index += 1) {
        const path_ptr = sysroot_paths[path_index];
        const path = std.mem.span(path_ptr);
        if (std.mem.eql(u8, path, "--link")) {
            const to = std.mem.span(sysroot_paths[path_index + 1]);
            const from = std.mem.span(sysroot_paths[path_index + 2]);
            path_index += 2;
            std.log.info("ln -s '{s}' '{s}'", .{ to, from });
            var from_path_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
            const from_path = try std.fmt.bufPrintZ(&from_path_buf, "{s}{s}", .{ sysroot_path, from });
            if (std.fs.path.dirname(from_path)) |from_dir| {
                try std.fs.cwd().makePath(from_dir);
            }
            switch (posix.errno(os.linux.symlink(to, from_path))) {
                .SUCCESS => {},
                else => |errno| {
                    std.log.err("symlink from '{s}' to '{s}' failed, errno={}", .{ from_path, to, errno });
                    posix.exit(0xff);
                },
            }
            continue;
        }

        if (std.mem.eql(u8, path, "--bind-mount-host")) {
            const src = std.mem.span(sysroot_paths[path_index + 1]);
            const dst_sysroot_relative = std.mem.span(sysroot_paths[path_index + 2]);
            path_index += 2;

            if (!std.mem.startsWith(u8, dst_sysroot_relative, "/")) {
                std.log.err("both paths in --bind-mount-host must be absolute but dst is '{s}'", .{dst_sysroot_relative});
                posix.exit(0xff);
            }

            var dst_sysroot_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
            const dst_sysroot = try std.fmt.bufPrintZ(&dst_sysroot_buf, "{s}{s}", .{ sysroot_path, dst_sysroot_relative });
            std.log.info("mkdir -p '{s}'", .{dst_sysroot});
            try std.fs.cwd().makePath(dst_sysroot);

            const opt_mount_options = getMountOptions(
                mount_options_list,
                &mount_option_index,
                path_index,
            );
            if (opt_mount_options) |mount_options| {
                std.log.info("mount --bind '{s}' to '{s}' with options '{s}'", .{ src, dst_sysroot, mount_options.cmdline_str });
            } else {
                std.log.info("mount --bind '{s}' to '{s}'", .{ src, dst_sysroot });
            }

            var flags: u32 = os.linux.MS.BIND;
            var mount_data: ?[*:0]const u8 = null;
            if (opt_mount_options) |mount_options| {
                flags |= mount_options.flags;
                mount_data = mount_options.data;
            }
            switch (posix.errno(os.linux.mount(src, dst_sysroot, mount_data, flags, 0))) {
                .SUCCESS => {},
                else => |errno| {
                    std.log.err("mount failed with E{s}", .{@tagName(errno)});
                    posix.exit(0xff);
                },
            }
            continue;
        }

        if (std.mem.eql(u8, path, "--tmpfs")) {
            const tmpfs_cmdline = std.mem.span(sysroot_paths[path_index + 1]);
            path_index += 1;
            if (!std.mem.startsWith(u8, tmpfs_cmdline, "/")) {
                std.log.err("both paths in --bind-mount-host must be absolute but dst is '{s}'", .{tmpfs_cmdline});
                posix.exit(0xff);
            }
            var tmpfs_path_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
            const tmpfs_path = try std.fmt.bufPrintZ(&tmpfs_path_buf, "{s}{s}", .{ sysroot_path, tmpfs_cmdline });
            std.log.info("mkdir -p '{s}'", .{tmpfs_path});
            try std.fs.cwd().makePath(tmpfs_path);

            const opt_mount_options = getMountOptions(
                mount_options_list,
                &mount_option_index,
                path_index,
            );
            if (opt_mount_options) |mount_options| {
                std.log.info("mounting tmpfs '{s}' with options '{s}'", .{ tmpfs_path, mount_options.cmdline_str });
            } else {
                std.log.info("mounting tmpfs '{s}'", .{tmpfs_path});
            }

            var flags: u32 = 0;
            var mount_data: ?[*:0]const u8 = null;
            if (opt_mount_options) |mount_options| {
                flags |= mount_options.flags;
                mount_data = mount_options.data;
            }
            switch (posix.errno(os.linux.mount("none", tmpfs_path, "tmpfs", flags, 0))) {
                .SUCCESS => {},
                else => |errno| {
                    std.log.err("mount tmpfs failed with E{s}", .{@tagName(errno)});
                    posix.exit(0xff);
                },
            }

            continue;
        }

        var stat: os.linux.Stat = undefined;
        switch (posix.errno(os.linux.stat(path_ptr, &stat))) {
            .SUCCESS => {},
            else => |errno| {
                std.log.err("stat '{s}' failed with E{s}", .{ path_ptr, @tagName(errno) });
                posix.exit(0xff);
            },
        }

        var path_in_sysroot_buf: [std.fs.max_path_bytes]u8 = undefined;
        const path_in_sysroot = blk: {
            if (std.mem.startsWith(u8, path, "/"))
                break :blk try std.fmt.bufPrintZ(&path_in_sysroot_buf, "{s}{s}", .{ sysroot_path, path });
            var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
            const cwd = try posix.getcwd(&cwd_buf);
            if (std.mem.eql(u8, path, ".")) {
                break :blk try std.fmt.bufPrintZ(&path_in_sysroot_buf, "{s}{s}", .{ sysroot_path, cwd });
            }
            break :blk try std.fmt.bufPrintZ(&path_in_sysroot_buf, "{s}{s}/{s}", .{ sysroot_path, cwd, path });
        };

        if ((stat.mode & os.linux.S.IFREG) != 0) {
            if (std.fs.path.dirname(path_in_sysroot)) |parent_dir_in_sysroot| {
                std.log.info("mkdir -p {s}...", .{parent_dir_in_sysroot});
                try std.fs.cwd().makePath(parent_dir_in_sysroot);
            }
            std.log.info("copying file '{s}'", .{path});
            var src_file = try std.fs.cwd().openFile(path, .{});
            defer src_file.close();
            var dst_file = try std.fs.cwd().createFile(path_in_sysroot, .{});
            defer dst_file.close();
            var buf: [@max(std.heap.page_size_min, 4096)]u8 = undefined;
            var total_copied: u64 = 0;
            while (true) {
                const len = try posix.read(src_file.handle, &buf);
                if (len == 0) break;
                try dst_file.writer().writeAll(buf[0..len]);
                total_copied += len;
            }
            std.log.info("copied {} bytes", .{total_copied});
            try posix.fchmod(dst_file.handle, stat.mode);
        } else if ((stat.mode & os.linux.S.IFDIR) != 0) {
            std.log.info("mkdir -p '{s}'", .{path_in_sysroot});
            std.fs.cwd().makePath(path_in_sysroot) catch |err| {
                std.log.err("mkdir -p '{s}' failed with {s}", .{ path_in_sysroot, @errorName(err) });
                posix.exit(0xff);
            };

            const opt_mount_options = getMountOptions(
                mount_options_list,
                &mount_option_index,
                path_index,
            );

            if (opt_mount_options) |mount_options| {
                std.log.info("mount --bind '{s}' to '{s}' with options '{s}'", .{ path, path_in_sysroot, mount_options.cmdline_str });
            } else {
                std.log.info("mount --bind '{s}' to '{s}'", .{ path, path_in_sysroot });
            }

            var flags: u32 = os.linux.MS.BIND;
            var mount_data: ?[*:0]const u8 = null;
            if (opt_mount_options) |mount_options| {
                flags |= mount_options.flags;
                mount_data = mount_options.data;
            }

            switch (posix.errno(os.linux.mount(path, path_in_sysroot, mount_data, flags, 0))) {
                .SUCCESS => {},
                else => |errno| {
                    // for some reason I can bind mount /proc on my NixOS machine but not my Ubuntu machine?
                    if (std.mem.eql(u8, path, "/proc")) {
                        std.log.warn("failed to bind mount /proc with E{s}, gonna try to mount it directly", .{@tagName(errno)});
                        switch (posix.errno(os.linux.mount("none", "/proc", null, os.linux.MS.PRIVATE | os.linux.MS.REC, 0))) {
                            .SUCCESS => {},
                            else => |errno2| {
                                std.log.warn("failed to mount it directly(at 0) also with E{s}", .{@tagName(errno2)});
                                try shell("sh");
                                posix.exit(0xff);
                            },
                        }
                        switch (posix.errno(os.linux.mount("proc", path_in_sysroot, "proc", os.linux.MS.NOSUID | os.linux.MS.NOEXEC | os.linux.MS.NODEV, 0))) {
                            .SUCCESS => {},
                            else => |errno2| {
                                std.log.warn("failed to mount it directly(at 1) also with E{s}", .{@tagName(errno2)});
                                try shell("sh");
                                posix.exit(0xff);
                            },
                        }
                        continue;
                    }
                    std.log.err("mount '{s}' to '{s}' flags=0x{x} failed, errno=E{s}", .{ path, path_in_sysroot, flags, @tagName(errno) });
                    posix.exit(0xff);
                },
            }
        } else {
            std.log.err("unknown file type 0x{x}", .{stat.mode & os.linux.S.IFMT});
            posix.exit(0xff);
        }
    }

    var cwd_path_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const cwd_path = try std.process.getCwd(cwd_path_buf[0 .. cwd_path_buf.len - 1]);
    cwd_path_buf[cwd_path.len] = 0;
    {
        var sysroot_cwd_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const sysroot_cwd_path = try std.fmt.bufPrintZ(&sysroot_cwd_path_buf, "{s}{s}", .{ sysroot_path, cwd_path });
        std.log.info("creating {s}...", .{sysroot_cwd_path});
        try std.fs.cwd().makePath(sysroot_cwd_path);
    }

    // TODO: make an option to disable this for debugging purposes and such
    //       we might be able to do this after chrooting
    if (opt.keep_readwrite) {
        std.log.warn("keeping veil root writable", .{});
    } else {
        std.log.info("remounting veil root as readonly...", .{});
        switch (posix.errno(os.linux.mount("none", sysroot_path, null, os.linux.MS.REMOUNT | os.linux.MS.RDONLY, 0))) {
            .SUCCESS => {},
            else => |errno| {
                std.log.err("remount viel root as readonly failed with E{s}", .{@tagName(errno)});
                posix.exit(0xff);
            },
        }
    }

    //try shell();

    switch (posix.errno(os.linux.chroot(sysroot_path))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("chroot '{s}' failed, errno={}", .{ sysroot_path, errno });
            posix.exit(0xff);
        },
    }
    std.log.info("chroot successful!", .{});

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

fn getMountOptions(
    mount_options_list: std.ArrayListUnmanaged(MountOptions),
    mount_option_index: *usize,
    path_index: usize,
) ?*MountOptions {
    while (true) {
        if (mount_option_index.* == mount_options_list.items.len) return null;
        const current = &mount_options_list.items[mount_option_index.*];
        if (path_index < current.start) return null;
        if (current.end) |end| {
            if (path_index >= end) {
                mount_option_index.* += 1;
                continue;
            }
        }
        return current;
    }
}

const MountOptions = struct {
    cmdline_str: [:0]u8,
    start: usize,
    flags: u32,
    data: ?[*:0]const u8,
    end: ?usize = null,
    pub fn init(cmdline_str_ptr: [*:0]u8, start: usize) MountOptions {
        const cmdline_str = std.mem.span(cmdline_str_ptr);
        var flags: u32 = 0;

        var it = std.mem.splitScalar(u8, cmdline_str, ',');
        while (it.next()) |opt_str| {
            if (std.mem.eql(u8, opt_str, "nosuid")) {
                flags |= os.linux.MS.NOSUID;
            } else if (std.mem.eql(u8, opt_str, "noexec")) {
                flags |= os.linux.MS.NOEXEC;
            } else if (std.mem.eql(u8, opt_str, "nodev")) {
                flags |= os.linux.MS.NODEV;
            } else if (std.mem.eql(u8, opt_str, "private")) {
                flags |= os.linux.MS.PRIVATE;
            } else if (std.mem.eql(u8, opt_str, "recursive")) {
                flags |= os.linux.MS.REC;
            } else {
                std.log.err("unknown mount option '{s}'", .{opt_str});
                posix.exit(0xff);
            }
        }

        return MountOptions{
            .cmdline_str = cmdline_str,
            .start = start,
            .flags = flags,
            .data = null,
        };
    }
};

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

const Ids = struct {
    real: posix.uid_t,
    effective: posix.uid_t,
    saved: posix.uid_t,

    pub fn isSuid(self: Ids) bool {
        return self.real != self.effective or self.real != self.saved;
    }
};

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
