const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

pub const Ids = struct {
    real: linux.uid_t,
    effective: linux.uid_t,
    saved: linux.uid_t,

    pub fn isSuid(self: Ids) bool {
        return self.real != self.effective or self.real != self.saved;
    }
};

pub const MountOptions = struct {
    cmdline_str: [:0]const u8,
    flags: u32,
    data: ?[*:0]const u8,
    pub fn init(cmdline_str_ptr: [*:0]const u8) MountOptions {
        const cmdline_str = std.mem.span(cmdline_str_ptr);
        var flags: u32 = 0;

        var it = std.mem.splitScalar(u8, cmdline_str, ',');
        while (it.next()) |opt_str| {
            if (std.mem.eql(u8, opt_str, "nosuid")) {
                flags |= linux.MS.NOSUID;
            } else if (std.mem.eql(u8, opt_str, "noexec")) {
                flags |= linux.MS.NOEXEC;
            } else if (std.mem.eql(u8, opt_str, "nodev")) {
                flags |= linux.MS.NODEV;
            } else if (std.mem.eql(u8, opt_str, "private")) {
                flags |= linux.MS.PRIVATE;
            } else if (std.mem.eql(u8, opt_str, "recursive")) {
                flags |= linux.MS.REC;
            } else {
                std.log.err("unknown mount option '{s}'", .{opt_str});
                std.process.exit(0xff);
            }
        }

        return MountOptions{
            .cmdline_str = cmdline_str,
            .flags = flags,
            .data = null,
        };
    }
};

/// A command-line argument before "--" along with its option arguments.
pub const Arg = union(enum) {
    path: [*:0]const u8,
    link: struct { target: [*:0]const u8, name: [*:0]const u8 },
    bind_mount_host: struct { src: [*:0]const u8, dst: [*:0]const u8 },
    tmpfs: [*:0]const u8,
    start_mount_opt: MountOptions,
    end_mount_opt,
    keep_rw,
    tmp_sysroot: [*:0]const u8,
};

pub const ArgIterator = struct {
    args: []const [*:0]const u8,
    index: usize = 0,

    pub fn next(it: *ArgIterator) ?Arg {
        if (it.index >= it.args.len) return null;
        const arg = std.mem.span(it.args[it.index]);
        it.index += 1;
        if (std.mem.eql(u8, arg, "--link")) return .{ .link = .{
            .target = it.optionArg(arg),
            .name = it.optionArg(arg),
        } };
        if (std.mem.eql(u8, arg, "--bind-mount-host")) return .{ .bind_mount_host = .{
            .src = it.optionArg(arg),
            .dst = it.optionArg(arg),
        } };
        if (std.mem.eql(u8, arg, "--tmpfs")) return .{ .tmpfs = it.optionArg(arg) };
        if (std.mem.eql(u8, arg, "--start-mount-opt")) return .{ .start_mount_opt = .init(it.optionArg(arg)) };
        if (std.mem.eql(u8, arg, "--end-mount-opt")) return .end_mount_opt;
        if (std.mem.eql(u8, arg, "--keep-rw")) return .keep_rw;
        if (std.mem.eql(u8, arg, "--tmp-sysroot")) return .{ .tmp_sysroot = it.optionArg(arg) };
        return .{ .path = arg.ptr };
    }

    fn optionArg(it: *ArgIterator, option: []const u8) [*:0]const u8 {
        if (it.index >= it.args.len) {
            std.log.err("command-line option '{s}' requires an argument", .{option});
            std.process.exit(0xff);
        }
        defer it.index += 1;
        return it.args[it.index];
    }
};

pub const Args = struct {
    pre_unshare_uids: Ids,
    pre_unshare_gids: Ids,
    /// the command-line arguments before "--", already validated by main
    veil_args: []const [*:0]const u8,
    sysroot_path: [:0]const u8,
    keep_readwrite: bool,
};

pub fn run(
    io: Io,
    wait_fd: linux.fd_t,
    parent_pid: linux.pid_t,
    args: *const Args,
) !void {
    std.log.info("broker: waiting for parent {} to signal eventfd", .{parent_pid});

    {
        var buf: [8]u8 = undefined;
        const rc = linux.read(wait_fd, &buf, buf.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| {
                std.log.err("broker: eventfd read failed, errno={}", .{e});
                std.process.exit(0xff);
            },
        }
        if (rc != @sizeOf(u64)) {
            std.log.err("broker: eventfd read returned {} bytes, expected {}", .{ rc, @sizeOf(u64) });
            std.process.exit(0xff);
        }
    }
    closeFd(wait_fd);

    // Write the parent's id maps.
    {
        var path_buf: [64]u8 = undefined;
        const sg_path = std.mem.printSentinel(&path_buf, "/proc/{}/setgroups", .{parent_pid}, 0) catch unreachable;
        writeProcFile(sg_path, "deny");
    }
    {
        var path_buf: [64]u8 = undefined;
        const uid_path = std.mem.printSentinel(&path_buf, "/proc/{}/uid_map", .{parent_pid}, 0) catch unreachable;
        writeIdMap(uid_path, args.pre_unshare_uids.real, args.pre_unshare_uids.real);
    }
    {
        var path_buf: [64]u8 = undefined;
        const gid_path = std.mem.printSentinel(&path_buf, "/proc/{}/gid_map", .{parent_pid}, 0) catch unreachable;
        writeIdMap(gid_path, 0, args.pre_unshare_gids.real);
    }

    // Enter the parent's user and mount namespaces so we can do mounts.
    enterNamespaces(parent_pid);

    // Do all mount operations from inside the parent's namespaces.
    setupSysroot(io, args.veil_args, args.sysroot_path, args.keep_readwrite) catch |err| {
        std.log.err("broker: setupSysroot failed: {s}", .{@errorName(err)});
        std.process.exit(0xff);
    };

    std.process.exit(0);
}

pub fn closeFd(fd: linux.fd_t) void {
    switch (linux.errno(linux.close(fd))) {
        // linux has closed the fd even on INTR, see https://github.com/ziglang/zig/issues/2425
        .SUCCESS, .INTR => {},
        // our fds are eventfds and procfs files, any error is a bug
        else => |e| std.debug.panic("close fd {} failed, errno={}", .{ fd, e }),
    }
}

fn openOrExit(path: [:0]const u8, flags: linux.O) linux.fd_t {
    const rc = linux.open(path, flags, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => |e| {
            std.log.err("broker: open '{s}' failed, errno={}", .{ path, e });
            std.process.exit(0xff);
        },
    };
}

// procfs files like uid_map must be written with a single write call.
fn writeProcFile(path: [:0]const u8, content: []const u8) void {
    const fd = openOrExit(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true });
    defer closeFd(fd);
    const rc = linux.write(fd, content.ptr, content.len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| {
            std.log.err("broker: write '{s}' to '{s}' failed, errno={}", .{ content, path, e });
            std.process.exit(0xff);
        },
    }
    if (rc != content.len) {
        std.log.err("broker: write to '{s}' returned {} bytes, expected {}", .{ path, rc, content.len });
        std.process.exit(0xff);
    }
}

fn enterNamespaces(parent_pid: linux.pid_t) void {
    {
        var ns_path_buf: [64]u8 = undefined;
        const user_ns_path = std.mem.printSentinel(&ns_path_buf, "/proc/{}/ns/user", .{parent_pid}, 0) catch unreachable;
        const user_fd = openOrExit(user_ns_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
        defer closeFd(user_fd);
        switch (linux.errno(linux.syscall2(.setns, @as(usize, @intCast(user_fd)), linux.CLONE.NEWUSER))) {
            .SUCCESS => {},
            else => |e| {
                std.log.err("broker: setns user failed: E{s}", .{@tagName(e)});
                std.process.exit(0xff);
            },
        }
    }
    {
        var ns_path_buf: [64]u8 = undefined;
        const mnt_ns_path = std.mem.printSentinel(&ns_path_buf, "/proc/{}/ns/mnt", .{parent_pid}, 0) catch unreachable;
        const mnt_fd = openOrExit(mnt_ns_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
        defer closeFd(mnt_fd);
        switch (linux.errno(linux.syscall2(.setns, @as(usize, @intCast(mnt_fd)), linux.CLONE.NEWNS))) {
            .SUCCESS => {},
            else => |e| {
                std.log.err("broker: setns mnt failed: E{s}", .{@tagName(e)});
                std.process.exit(0xff);
            },
        }
    }
}

fn setupSysroot(
    io: Io,
    veil_args: []const [*:0]const u8,
    sysroot_path: [:0]const u8,
    keep_readwrite: bool,
) !void {
    std.log.info("marking all mounts as private", .{});
    switch (linux.errno(linux.mount("none", "/", null, linux.MS.REC | linux.MS.PRIVATE, 0))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("mount MS_REC|MS_PRIVATE failed with E{s}", .{@tagName(errno)});
            return error.MountFailed;
        },
    }

    std.log.info("mounting the new sysroot as a tmpfs to '{s}'", .{sysroot_path});
    switch (linux.errno(linux.mount("none", sysroot_path, "tmpfs", 0, 0))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("mount tmpfs failed with E{s}", .{@tagName(errno)});
            return error.MountFailed;
        },
    }

    // shell("sh");
    var opt_mount_options: ?MountOptions = null;

    var arg_it: ArgIterator = .{ .args = veil_args };
    while (arg_it.next()) |arg| switch (arg) {
        .start_mount_opt => |mount_options| opt_mount_options = mount_options,
        .end_mount_opt => opt_mount_options = null,
        .keep_rw, .tmp_sysroot => {},
        .link => |link| {
            const to = std.mem.span(link.target);
            const from = std.mem.span(link.name);
            std.log.info("ln -s '{s}' '{s}'", .{ to, from });
            var from_path_buf: [Io.Dir.max_path_bytes + 1]u8 = undefined;
            const from_path = try std.mem.printSentinel(&from_path_buf, "{s}{s}", .{ sysroot_path, from }, 0);
            if (std.fs.path.dirname(from_path)) |from_dir| {
                try makePath(io, from_dir);
            }
            switch (linux.errno(linux.symlinkat(to, linux.AT.FDCWD, from_path))) {
                .SUCCESS => {},
                else => |errno| {
                    std.log.err("symlink from '{s}' to '{s}' failed, errno={}", .{ from_path, to, errno });
                    std.process.exit(0xff);
                },
            }
        },
        .bind_mount_host => |bind| {
            const src = std.mem.span(bind.src);
            const dst_sysroot_relative = std.mem.span(bind.dst);

            if (!std.mem.startsWith(u8, dst_sysroot_relative, "/")) {
                std.log.err("both paths in --bind-mount-host must be absolute but dst is '{s}'", .{dst_sysroot_relative});
                std.process.exit(0xff);
            }

            var dst_sysroot_buf: [Io.Dir.max_path_bytes + 1]u8 = undefined;
            const dst_sysroot = try std.mem.printSentinel(&dst_sysroot_buf, "{s}{s}", .{ sysroot_path, dst_sysroot_relative }, 0);
            std.log.info("mkdir -p '{s}'", .{dst_sysroot});
            try makePath(io, dst_sysroot);
            if (opt_mount_options) |mount_options| {
                std.log.info("mount --bind '{s}' to '{s}' with options '{s}'", .{ src, dst_sysroot, mount_options.cmdline_str });
            } else {
                std.log.info("mount --bind '{s}' to '{s}'", .{ src, dst_sysroot });
            }

            var flags: u32 = linux.MS.BIND;
            var mount_data: ?[*:0]const u8 = null;
            if (opt_mount_options) |mount_options| {
                flags |= mount_options.flags;
                mount_data = mount_options.data;
            }
            switch (linux.errno(linux.mount(src, dst_sysroot, mount_data, flags, 0))) {
                .SUCCESS => {},
                else => |errno| {
                    std.log.err("mount failed with E{s}", .{@tagName(errno)});
                    std.process.exit(0xff);
                },
            }
        },
        .tmpfs => |tmpfs_cmdline_ptr| {
            const tmpfs_cmdline = std.mem.span(tmpfs_cmdline_ptr);
            if (!std.mem.startsWith(u8, tmpfs_cmdline, "/")) {
                std.log.err("both paths in --bind-mount-host must be absolute but dst is '{s}'", .{tmpfs_cmdline});
                std.process.exit(0xff);
            }
            var tmpfs_path_buf: [Io.Dir.max_path_bytes + 1]u8 = undefined;
            const tmpfs_path = try std.mem.printSentinel(&tmpfs_path_buf, "{s}{s}", .{ sysroot_path, tmpfs_cmdline }, 0);
            std.log.info("mkdir -p '{s}'", .{tmpfs_path});
            try makePath(io, tmpfs_path);
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
            switch (linux.errno(linux.mount("none", tmpfs_path, "tmpfs", flags, 0))) {
                .SUCCESS => {},
                else => |errno| {
                    std.log.err("mount tmpfs failed with E{s}", .{@tagName(errno)});
                    std.process.exit(0xff);
                },
            }
        },
        .path => |path_ptr| {
            const path = std.mem.span(path_ptr);
            const stat = Io.Dir.cwd().statFile(io, path, .{}) catch |err| {
                std.log.err("stat '{s}' failed with {t}", .{ path, err });
                std.process.exit(0xff);
            };

            var path_in_sysroot_buf: [Io.Dir.max_path_bytes]u8 = undefined;
            const path_in_sysroot = blk: {
                if (std.mem.startsWith(u8, path, "/"))
                    break :blk try std.mem.printSentinel(&path_in_sysroot_buf, "{s}{s}", .{ sysroot_path, path }, 0);
                var cwd_buf: [Io.Dir.max_path_bytes]u8 = undefined;
                const cwd = cwd_buf[0..try std.process.currentPath(io, &cwd_buf)];
                if (std.mem.eql(u8, path, ".")) {
                    break :blk try std.mem.printSentinel(&path_in_sysroot_buf, "{s}{s}", .{ sysroot_path, cwd }, 0);
                }
                break :blk try std.mem.printSentinel(&path_in_sysroot_buf, "{s}{s}/{s}", .{ sysroot_path, cwd, path }, 0);
            };

            if (stat.kind == .file) {
                if (std.fs.path.dirname(path_in_sysroot)) |parent_dir_in_sysroot| {
                    std.log.info("mkdir -p {s}...", .{parent_dir_in_sysroot});
                    try makePath(io, parent_dir_in_sysroot);
                }
                std.log.info("copying file '{s}'", .{path});
                const src_file = try Io.Dir.cwd().openFile(io, path, .{});
                defer src_file.close(io);
                const dst_file = try Io.Dir.cwd().createFile(io, path_in_sysroot, .{});
                defer dst_file.close(io);
                const total_copied = try copyFileToSysroot(io, src_file, dst_file);
                std.log.info("copied {} bytes", .{total_copied});
                try dst_file.setPermissions(io, stat.permissions);
            } else if (stat.kind == .directory) {
                std.log.info("mkdir -p '{s}'", .{path_in_sysroot});
                makePath(io, path_in_sysroot) catch |err| {
                    std.log.err("mkdir -p '{s}' failed with {s}", .{ path_in_sysroot, @errorName(err) });
                    std.process.exit(0xff);
                };

                if (opt_mount_options) |mount_options| {
                    std.log.info("mount --bind '{s}' to '{s}' with options '{s}'", .{ path, path_in_sysroot, mount_options.cmdline_str });
                } else {
                    std.log.info("mount --bind '{s}' to '{s}'", .{ path, path_in_sysroot });
                }

                var flags: u32 = linux.MS.BIND;
                var mount_data: ?[*:0]const u8 = null;
                if (opt_mount_options) |mount_options| {
                    flags |= mount_options.flags;
                    mount_data = mount_options.data;
                }

                switch (linux.errno(linux.mount(path, path_in_sysroot, mount_data, flags, 0))) {
                    .SUCCESS => {},
                    else => |errno| {
                        // for some reason I can bind mount /proc on my NixOS machine but not my Ubuntu machine?
                        if (std.mem.eql(u8, path, "/proc")) {
                            std.log.warn("failed to bind mount /proc with E{s}, gonna try to mount it directly", .{@tagName(errno)});
                            switch (linux.errno(linux.mount("none", "/proc", null, linux.MS.PRIVATE | linux.MS.REC, 0))) {
                                .SUCCESS => {},
                                else => |errno2| {
                                    std.log.warn("failed to mount it directly(at 0) also with E{s}", .{@tagName(errno2)});
                                    shell(io, "sh");
                                    std.process.exit(0xff);
                                },
                            }
                            switch (linux.errno(linux.mount("proc", path_in_sysroot, "proc", linux.MS.NOSUID | linux.MS.NOEXEC | linux.MS.NODEV, 0))) {
                                .SUCCESS => {},
                                else => |errno2| {
                                    std.log.warn("failed to mount it directly(at 1) also with E{s}", .{@tagName(errno2)});
                                    shell(io, "sh");
                                    std.process.exit(0xff);
                                },
                            }
                            continue;
                        }
                        std.log.err("mount '{s}' to '{s}' flags=0x{x} failed, errno=E{s}", .{ path, path_in_sysroot, flags, @tagName(errno) });
                        std.process.exit(0xff);
                    },
                }
            } else {
                std.log.err("'{s}' has unsupported file type {t}", .{ path, stat.kind });
                std.process.exit(0xff);
            }
        },
    };

    var cwd_path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const cwd_path = cwd_path_buf[0..try std.process.currentPath(io, &cwd_path_buf)];
    {
        var sysroot_cwd_path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const sysroot_cwd_path = try std.mem.printSentinel(&sysroot_cwd_path_buf, "{s}{s}", .{ sysroot_path, cwd_path }, 0);
        std.log.info("creating {s}...", .{sysroot_cwd_path});
        try makePath(io, sysroot_cwd_path);
    }

    // TODO: make an option to disable this for debugging purposes and such
    //       we might be able to do this after chrooting
    if (keep_readwrite) {
        std.log.warn("keeping veil root writable", .{});
    } else {
        std.log.info("remounting veil root as readonly...", .{});
        switch (linux.errno(linux.mount("none", sysroot_path, null, linux.MS.REMOUNT | linux.MS.RDONLY, 0))) {
            .SUCCESS => {},
            else => |errno| {
                std.log.err("remount viel root as readonly failed with E{s}", .{@tagName(errno)});
                std.process.exit(0xff);
            },
        }
    }

    // shell("sh");

    switch (linux.errno(linux.chroot(sysroot_path))) {
        .SUCCESS => {},
        else => |errno| {
            std.log.err("chroot '{s}' failed, errno={}", .{ sysroot_path, errno });
            std.process.exit(0xff);
        },
    }
    std.log.info("chroot successful!", .{});
}

fn writeIdMap(path: [:0]const u8, id_inside: linux.uid_t, id_outside: linux.uid_t) void {
    var buf: [200]u8 = undefined;
    const content = std.mem.print(&buf, "{} {} 1", .{ id_inside, id_outside }) catch unreachable;
    writeProcFile(path, content);
}

fn copyFileToSysroot(io: Io, src_file: Io.File, dst_file: Io.File) !u64 {
    var reader = src_file.reader(io, &.{});
    var write_buf: [@max(std.heap.page_size_min, 4096)]u8 = undefined;
    var writer = dst_file.writer(io, &write_buf);
    const total_copied = writer.interface.sendFileAll(&reader, .unlimited) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.WriteFailed => return writer.err.?,
    };
    writer.interface.flush() catch return writer.err.?;
    return total_copied;
}

fn shell(io: Io, name: []const u8) void {
    var child = std.process.spawn(io, .{ .argv = &.{name} }) catch return;
    const result = child.wait(io) catch return;
    std.log.info("shell exited with {}", .{result});
    std.process.exit(0);
}

// zig 0.15's makePath used 0o755, 0.17's createDirPath defaults to 0o777.
fn makePath(io: Io, path: []const u8) !void {
    _ = try Io.Dir.cwd().createDirPathStatus(io, path, .fromMode(0o755));
}
