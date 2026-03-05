const std = @import("std");
const os = std.os;
const posix = std.posix;

pub const Ids = struct {
    real: posix.uid_t,
    effective: posix.uid_t,
    saved: posix.uid_t,

    pub fn isSuid(self: Ids) bool {
        return self.real != self.effective or self.real != self.saved;
    }
};

pub const MountOptions = struct {
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

pub const Args = struct {
    pre_unshare_uids: Ids,
    pre_unshare_gids: Ids,
    sysroot_paths: [][*:0]u8,
    mount_options_list: std.ArrayListUnmanaged(MountOptions),
    sysroot_path: [:0]const u8,
    keep_readwrite: bool,
};

const zig_atleast_15 = @import("builtin").zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;

pub fn run(
    wait_fd: posix.fd_t,
    parent_pid: posix.pid_t,
    args: *const Args,
) !void {
    std.log.info("broker: waiting for parent {} to signal eventfd", .{parent_pid});

    {
        var buf: [8]u8 = undefined;
        const n = posix.read(wait_fd, &buf) catch |err| {
            std.log.err("broker: eventfd read failed: {s}", .{@errorName(err)});
            posix.exit(0xff);
        };
        if (n != @sizeOf(u64)) {
            std.log.err("broker: eventfd read returned {} bytes, expected {}", .{ n, @sizeOf(u64) });
            posix.exit(0xff);
        }
    }
    posix.close(wait_fd);

    // Write the parent's id maps.
    {
        var path_buf: [64]u8 = undefined;
        const sg_path = std.fmt.bufPrintZ(&path_buf, "/proc/{}/setgroups", .{parent_pid}) catch unreachable;
        const fd = try posixOpen(sg_path, .{ .ACCMODE = .WRONLY }, 0);
        defer posix.close(fd);
        const content = "deny";
        const written = try posix.write(fd, content);
        if (written != content.len) {
            std.log.err("broker: write to '{s}' returned {} bytes, expected {}", .{ sg_path, written, content.len });
            return error.ShortWrite;
        }
    }
    {
        var path_buf: [64]u8 = undefined;
        const uid_path = std.fmt.bufPrintZ(&path_buf, "/proc/{}/uid_map", .{parent_pid}) catch unreachable;
        writeIdMap(uid_path, args.pre_unshare_uids.real, args.pre_unshare_uids.real) catch |err| {
            std.log.err("broker: failed to write '{s}': {s}", .{ uid_path, @errorName(err) });
            posix.exit(0xff);
        };
    }
    {
        var path_buf: [64]u8 = undefined;
        const gid_path = std.fmt.bufPrintZ(&path_buf, "/proc/{}/gid_map", .{parent_pid}) catch unreachable;
        writeIdMap(gid_path, 0, args.pre_unshare_gids.real) catch |err| {
            std.log.err("broker: failed to write '{s}': {s}", .{ gid_path, @errorName(err) });
            posix.exit(0xff);
        };
    }

    // Enter the parent's user and mount namespaces so we can do mounts.
    enterNamespaces(parent_pid);

    // Do all mount operations from inside the parent's namespaces.
    setupSysroot(args.sysroot_paths, args.mount_options_list, args.sysroot_path, args.keep_readwrite) catch |err| {
        std.log.err("broker: setupSysroot failed: {s}", .{@errorName(err)});
        posix.exit(0xff);
    };

    posix.exit(0);
}

fn posixOpen(path: [:0]const u8, opt: std.posix.O, perm: std.posix.mode_t) std.posix.OpenError!std.posix.fd_t {
    return posix.open(path, opt, perm) catch |err| {
        std.log.err("open '{s}' failed, error={s}", .{ path, @errorName(err) });
        return err;
    };
}

fn enterNamespaces(parent_pid: posix.pid_t) void {
    {
        var ns_path_buf: [64]u8 = undefined;
        const user_ns_path = std.fmt.bufPrintZ(&ns_path_buf, "/proc/{}/ns/user", .{parent_pid}) catch unreachable;
        const user_fd = posixOpen(user_ns_path, .{ .ACCMODE = .RDONLY }, 0) catch posix.exit(0xff);
        defer posix.close(user_fd);
        switch (posix.errno(os.linux.syscall2(.setns, @as(usize, @intCast(user_fd)), os.linux.CLONE.NEWUSER))) {
            .SUCCESS => {},
            else => |e| {
                std.log.err("broker: setns user failed: E{s}", .{@tagName(e)});
                posix.exit(0xff);
            },
        }
    }
    {
        var ns_path_buf: [64]u8 = undefined;
        const mnt_ns_path = std.fmt.bufPrintZ(&ns_path_buf, "/proc/{}/ns/mnt", .{parent_pid}) catch unreachable;
        const mnt_fd = posixOpen(mnt_ns_path, .{ .ACCMODE = .RDONLY }, 0) catch posix.exit(0xff);
        defer posix.close(mnt_fd);
        switch (posix.errno(os.linux.syscall2(.setns, @as(usize, @intCast(mnt_fd)), os.linux.CLONE.NEWNS))) {
            .SUCCESS => {},
            else => |e| {
                std.log.err("broker: setns mnt failed: E{s}", .{@tagName(e)});
                posix.exit(0xff);
            },
        }
    }
}

fn setupSysroot(
    sysroot_paths: [][*:0]u8,
    mount_options_list: std.ArrayListUnmanaged(MountOptions),
    sysroot_path: [:0]const u8,
    keep_readwrite: bool,
) !void {
    std.log.info("marking all mounts as private", .{});
    switch (posix.errno(os.linux.mount("none", "/", null, os.linux.MS.REC | os.linux.MS.PRIVATE, 0))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("mount MS_REC|MS_PRIVATE failed with E{s}", .{@tagName(errno)});
            return error.MountFailed;
        },
    }

    std.log.info("mounting the new sysroot as a tmpfs to '{s}'", .{sysroot_path});
    switch (posix.errno(os.linux.mount("none", sysroot_path, "tmpfs", 0, 0))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("mount tmpfs failed with E{s}", .{@tagName(errno)});
            return error.MountFailed;
        },
    }

    // shell("sh");
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
            const total_copied = try copyFileToSysroot(src_file, dst_file);
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
                                shell("sh");
                                posix.exit(0xff);
                            },
                        }
                        switch (posix.errno(os.linux.mount("proc", path_in_sysroot, "proc", os.linux.MS.NOSUID | os.linux.MS.NOEXEC | os.linux.MS.NODEV, 0))) {
                            .SUCCESS => {},
                            else => |errno2| {
                                std.log.warn("failed to mount it directly(at 1) also with E{s}", .{@tagName(errno2)});
                                shell("sh");
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
    if (keep_readwrite) {
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

    // shell("sh");

    switch (posix.errno(os.linux.chroot(sysroot_path))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("chroot '{s}' failed, errno={}", .{ sysroot_path, errno });
            posix.exit(0xff);
        },
    }
    std.log.info("chroot successful!", .{});
}

fn writeIdMap(path: [:0]const u8, id_inside: posix.uid_t, id_outside: posix.uid_t) !void {
    const fd = try posixOpen(path, .{ .ACCMODE = .WRONLY }, 0);
    defer posix.close(fd);
    var buf: [200]u8 = undefined;
    const content = try std.fmt.bufPrint(&buf, "{} {} 1", .{ id_inside, id_outside });
    const written = try posix.write(fd, content);
    if (written != content.len) {
        std.log.err("broker: write to '{s}' returned {} bytes, expected {}", .{ path, written, content.len });
        return error.ShortWrite;
    }
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

fn copyFileToSysroot(src_file: std.fs.File, dst_file: std.fs.File) !u64 {
    var total_copied: u64 = 0;
    if (zig_atleast_15) {
        var read_buf: [0]u8 = undefined;
        var reader = src_file.reader(&read_buf);
        var write_buf: [@max(std.heap.page_size_min, 4096)]u8 = undefined;
        var writer = dst_file.writer(&write_buf);
        while (true) {
            _ = reader.interface.stream(&writer.interface, .unlimited) catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => return reader.err orelse error.Unexpected,
                error.WriteFailed => return writer.err orelse error.Unexpected,
            };
        }
        writer.interface.flush() catch return writer.err orelse error.Unexpected;
    } else {
        var buf: [@max(std.heap.page_size_min, 4096)]u8 = undefined;
        while (true) {
            const len = try posix.read(src_file.handle, &buf);
            if (len == 0) break;
            try dst_file.writer().writeAll(buf[0..len]);
            total_copied += len;
        }
    }
    return total_copied;
}

fn shell(name: []const u8) void {
    var child = std.process.Child.init(&[_][]const u8{name}, std.heap.page_allocator);
    child.spawn() catch return;
    const result = child.wait() catch return;
    std.log.info("shell exited with {}", .{result});
    posix.exit(0);
}
