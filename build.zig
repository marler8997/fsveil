const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // staticio makes std.Io dispatch static so only the Io operations fsveil
    // reaches get compiled in, see std_options.io_vtable in fsveil.zig.
    const patched_std = b.dependency("patch", .{
        .std_patches = &[_]std.Build.LazyPath{
            b.dependency("staticio", .{}).namedLazyPath("std.patch"),
        },
    }).module("std");

    const exe = b.addExecutable(.{
        .name = "fsveil",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fsveil.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "std", .module = patched_std }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
