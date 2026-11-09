const std = @import("std");

pub fn build(b: *std.Build) void {
    const cross = b.option(bool, "all", "Build for all supported targets") orelse false;

    const targets: []const std.Target.Query = if (cross) &.{
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
        .{ .cpu_arch = .x86_64, .os_tag = .macos },
        .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
        .{ .cpu_arch = .wasm32, .os_tag = .wasi },
    } else &.{
        .{},
    };
    for (targets) |target| {
        const name = if (target.cpu_arch) |arch| switch (arch) {
            .wasm32 => "secret",
            else => b.fmt("secret-{s}-{s}", .{
                @tagName(arch),
                @tagName(target.os_tag.?),
            }),
        } else "secret";

        const exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .target = b.resolveTargetQuery(target),
                .optimize = .ReleaseSmall,
                .link_libc = true,
                .strip = cross,
            }),
        });
        exe.root_module.addCSourceFiles(.{
            .files = &.{"secret.c"},
            .flags = if (target.cpu_arch == .wasm32) &.{"-DNOMAIN"} else &.{},
        });
        if (target.cpu_arch == .wasm32) exe.wasi_exec_model = .reactor;
        b.installArtifact(exe);
    }
}
