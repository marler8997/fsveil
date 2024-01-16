const std = @import("std");
const os = std.os;

pub const log_level: std.log.Level = .warn;

fn usage() !void {
    try std.io.getStdErr().writer().writeAll(
        \\fsveil: Runs the given program with a veiled view of the filesystem
        \\
        \\Usage: fsveil [OPTIONS...] FILES/DIRS -- CMD...
        \\
        \\Options:
        \\    --link TARGET LINK_NAME                   Create symlink LINK_NAME -> TARGET inside the veil
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
        os.exit(0xff);
    }
    return os.argv[i.*];
}

pub fn main() !void {
    const Link = struct {
        to: [*:0]u8,
        from: [:0]u8,
    };
    var links = std.ArrayListUnmanaged(Link){};
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
                opt.next_argv = @ptrCast([*:null]?[*:0]u8, os.argv[arg_index + 1 ..].ptr);
                break;
            } else if (std.mem.eql(u8, arg, "--link")) {
                const to = getCmdlineOption(&arg_index);
                const from = std.mem.span(getCmdlineOption(&arg_index));
                try links.append(arena.allocator(), .{ .to = to, .from = from });
            } else if (std.mem.eql(u8, arg, "--keep-rw")) {
                opt.keep_readwrite = true;
            } else if (std.mem.eql(u8, arg, "--start-mount-opt")) {
                const cmdline_str = getCmdlineOption(&arg_index);
                try mount_options_list.append(arena.allocator(), MountOptions.init(cmdline_str, new_argc - 1));
            } else if (std.mem.eql(u8, arg, "--end-mount-opt")) {
                if (mount_options_list.items.len == 0) {
                    std.log.err("got --end-mount-opt without a corresponding --start-mount-opt", .{});
                    os.exit(0xff);
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
        os.exit(0xff);
    }
    const next_argv = opt.next_argv orelse {
        std.log.err("missing '--' to delineate a command to execute", .{});
        os.exit(0xff);
    };
    const next_program = next_argv[0] orelse {
        std.log.err("missing program after '--'", .{});
        os.exit(0xff);
    };
    const sysroot_paths = os.argv[1..new_argc];
    const sysroot_path = opt.tmp_sysroot orelse pickSysrootMount(sysroot_paths);

    const pre_unshare_uids = getUids();
    std.log.info("PreUnshare Uids: {}", .{pre_unshare_uids});
    const pre_unshare_gids = getGids();
    std.log.info("PreUnshare Gids: {}", .{pre_unshare_gids});

    // NEWPID might be necessary for mounting /proc in some cases
    switch (os.errno(os.linux.unshare(os.linux.CLONE.NEWUSER | os.linux.CLONE.NEWNS))) {
        .SUCCESS => {},
        else => |e| {
            std.log.err("unshare failed, errno={}", .{e});
            os.exit(0xff);
        },
    }
    {
        const uids = getUids();
        std.log.info("PostUnshare Uids: {}", .{uids});
    }
    {
        var fd = try os.open("/proc/self/setgroups", os.O.WRONLY, 0);
        defer os.close(fd);
        const content = "deny";
        const written = try os.write(fd, content);
        std.debug.assert(written == content.len);
    }
    {
        var fd = try os.open("/proc/self/uid_map", os.O.WRONLY, 0);
        defer os.close(fd);
        var buf: [200]u8 = undefined;
        const content = try std.fmt.bufPrint(&buf, "{} {0} 1", .{pre_unshare_uids.real});
        const written = try os.write(fd, content);
        std.debug.assert(written == content.len);
    }
    {
        const uids = getUids();
        std.log.info("PostSetUidMap Uids: {}", .{uids});
    }
    {
        var fd = try os.open("/proc/self/gid_map", os.O.WRONLY, 0);
        defer os.close(fd);
        var buf: [200]u8 = undefined;
        const content = try std.fmt.bufPrint(&buf, "0 {} 1", .{pre_unshare_gids.real});
        const written = try os.write(fd, content);
        std.debug.assert(written == content.len);
    }

    std.log.info("marking all mounts as private", .{});
    switch (os.errno(mount("none", "/", null, os.linux.MS.REC | os.linux.MS.PRIVATE, 0))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("mount failed with E{s}", .{@tagName(errno)});
            os.exit(0xff);
        },
    }

    std.log.info("mounting the new sysroot as a tmpfs to '{s}'", .{sysroot_path});
    switch (os.errno(os.linux.mount("none", sysroot_path, "tmpfs", 0, 0))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("mount failed with E{s}", .{@tagName(errno)});
            os.exit(0xff);
        },
    }

    //try shell("sh");
    var mount_option_index: usize = 0;

    for (sysroot_paths) |path_ptr, path_index| {
        var stat: os.linux.Stat = undefined;
        switch (os.errno(os.linux.stat(path_ptr, &stat))) {
            .SUCCESS => {},
            else => |errno| {
                std.log.err("stat '{s}' failed with E{s}", .{ path_ptr, @tagName(errno) });
                os.exit(0xff);
            },
        }

        const path = std.mem.span(path_ptr);
        var path_in_sysroot_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const path_in_sysroot = blk: {
            if (std.mem.startsWith(u8, path, "/"))
                break :blk try std.fmt.bufPrintZ(&path_in_sysroot_buf, "{s}{s}", .{ sysroot_path, path });
            var cwd_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const cwd = try std.os.getcwd(&cwd_buf);
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
            var buf: [std.mem.page_size]u8 = undefined;
            var total_copied: u64 = 0;
            while (true) {
                const len = try os.read(src_file.handle, &buf);
                if (len == 0) break;
                try dst_file.writer().writeAll(buf[0..len]);
                total_copied += len;
            }
            std.log.info("copied {} bytes", .{total_copied});
            try os.fchmod(dst_file.handle, stat.mode);
        } else if ((stat.mode & os.linux.S.IFDIR) != 0) {
            std.log.info("mkdir -p '{s}'", .{path_in_sysroot});
            std.fs.cwd().makePath(path_in_sysroot) catch |err| {
                std.log.err("mkdir -p '{s}' failed with {s}", .{path_in_sysroot, @errorName(err)});
                os.exit(0xff);
            };

            var opt_mount_options: ?*MountOptions = null;
            while (true) {
                if (mount_option_index == mount_options_list.items.len) break;
                const current = &mount_options_list.items[mount_option_index];
                if (path_index < current.start) break;
                if (current.end) |end| {
                    if (path_index >= end) {
                        mount_option_index += 1;
                        continue;
                    }
                }
                opt_mount_options = current;
                break;
            }

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

            switch (os.errno(mount(path, path_in_sysroot, mount_data, flags, 0))) {
                .SUCCESS => {},
                else => |errno| {
                    // for some reason I can bind mount /proc on my NixOS machine but not my Ubuntu machine?
                    if (std.mem.eql(u8, path, "/proc")) {
                        std.log.warn("failed to bind mount /proc with E{s}, gonna try to mount it directly", .{@tagName(errno)});
                        switch (os.errno(mount("none", "/proc", null, os.linux.MS.PRIVATE | os.linux.MS.REC, 0))) {
                            .SUCCESS => {},
                            else => |errno2| {
                                std.log.warn("failed to mount it directly(at 0) also with E{s}", .{@tagName(errno2)});
                                try shell("sh");
                                os.exit(0xff);
                            },
                        }
                        switch (os.errno(mount("proc", path_in_sysroot, "proc", os.linux.MS.NOSUID | os.linux.MS.NOEXEC | os.linux.MS.NODEV, 0))) {
                            .SUCCESS => {},
                            else => |errno2| {
                                std.log.warn("failed to mount it directly(at 1) also with E{s}", .{@tagName(errno2)});
                                try shell("sh");
                                os.exit(0xff);
                            },
                        }
                        continue;
                    }
                    std.log.err("mount '{s}' to '{s}' flags=0x{x} failed, errno=E{s}", .{path, path_in_sysroot, flags, @tagName(errno)});
                    os.exit(0xff);
                },
            }
        } else {
            std.log.err("unknown file type 0x{x}", .{stat.mode & os.linux.S.IFMT});
            os.exit(0xff);
        }
    }

    var cwd_path_buf: [std.fs.MAX_PATH_BYTES + 1]u8 = undefined;
    const cwd_path = try std.process.getCwd(cwd_path_buf[0 .. cwd_path_buf.len - 1]);
    cwd_path_buf[cwd_path.len] = 0;
    {
        var sysroot_cwd_path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const sysroot_cwd_path = try std.fmt.bufPrintZ(&sysroot_cwd_path_buf, "{s}{s}", .{ sysroot_path, cwd_path });
        std.log.info("creating {s}...", .{sysroot_cwd_path});
        try std.fs.cwd().makePath(sysroot_cwd_path);
    }

    for (links.items) |link| {
        std.log.info("ln -s '{s}' '{s}'", .{ std.mem.span(link.to), link.from });
        var from_path_buf: [std.fs.MAX_PATH_BYTES + 1]u8 = undefined;
        const from_path = try std.fmt.bufPrintZ(&from_path_buf, "{s}{s}", .{ sysroot_path, std.mem.span(link.from) });
        if (std.fs.path.dirname(from_path)) |from_dir| {
            try std.fs.cwd().makePath(from_dir);
        }
        switch (os.errno(os.linux.symlink(link.to, from_path))) {
            .SUCCESS => {},
            else => |errno| {
                std.log.err("symlink from '{s}' to '{s}' failed, errno={}", .{ from_path, std.mem.span(link.to), errno });
                os.exit(0xff);
            },
        }
    }

    // TODO: make an option to disable this for debugging purposes and such
    //       we might be able to do this after chrooting
    if (opt.keep_readwrite) {
        std.log.warn("keeping veil root writable", .{});
    } else {
        std.log.info("remounting veil root as readonly...", .{});
        switch (os.errno(mount("none", sysroot_path, null, os.linux.MS.REMOUNT | os.linux.MS.RDONLY, 0))) {
            .SUCCESS => {},
            else => |errno| {
                std.log.err("remount viel root as readonly failed with E{s}", .{@tagName(errno)});
                os.exit(0xff);
            },
        }
    }

    //try shell();

    switch (os.errno(os.linux.chroot(sysroot_path))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("chroot '{s}' failed, errno={}", .{ sysroot_path, errno });
            os.exit(0xff);
        },
    }
    std.log.info("chroot successful!", .{});

    std.log.info("cd '{s}'", .{cwd_path});
    try os.chdirZ(std.meta.assumeSentinel(cwd_path, 0));

    std.log.info("execve '{s}'", .{next_program});
    const errno = os.linux.execve(
        next_program,
        next_argv,
        @ptrCast([*:null]const ?[*:0]const u8, os.environ.ptr),
    );
    std.log.err("execve failed, errno={}", .{errno});
    os.exit(0xff);
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

        var it = std.mem.split(u8, cmdline_str, ",");
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
                os.exit(0xff);
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
    var child = std.ChildProcess.init(&[_][]const u8{name}, std.heap.page_allocator);
    try child.spawn();
    const result = try child.wait();
    std.log.info("shell exited with {}", .{result});
    os.exit(0);
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
    } else |_| { }
    if (std.fs.accessAbsolute("/tmp", .{})) {
        if (sysrootMountIsOk(sysroot_paths, "/tmp")) return "/tmp";
    } else |_| { }
    std.log.err("neither /mnt not /tmp can be used, TODO: maybe make a directory underneath /tmp?", .{});
    os.exit(0xff);
}

const Ids = struct {
    real: os.uid_t,
    effective: os.uid_t,
    saved: os.uid_t,

    pub fn isSuid(self: Ids) bool {
        return self.real != self.effective or self.real != self.saved;
    }
};

fn getUids() Ids {
    var ids: Ids = undefined;
    switch (os.errno(os.linux.getresuid(&ids.real, &ids.effective, &ids.saved))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("getresuid failed, errno={}", .{errno});
            os.exit(0xff);
        },
    }
    return ids;
}

fn getGids() Ids {
    var ids: Ids = undefined;
    switch (os.errno(os.linux.getresgid(&ids.real, &ids.effective, &ids.saved))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("getresgid failed, errno={}", .{errno});
            os.exit(0xff);
        },
    }
    return ids;
}

// TODO: workaround non-optional fstype argument: https://github.com/ziglang/zig/pull/11889
pub fn mount(special: [*:0]const u8, dir: [*:0]const u8, fstype: ?[*:0]const u8, flags: u32, data: usize) usize {
    return os.linux.syscall5(.mount, @ptrToInt(special), @ptrToInt(dir), @ptrToInt(fstype), flags, data);
}
