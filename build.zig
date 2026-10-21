const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zmx = b.dependency("zmx", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.addImport("libzmx", zmx.module("zmx"));
    exe_mod.addImport("zmx", zmx.module("zmx"));

    const exe = b.addExecutable(.{
        .name = "zmosh",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run zmosh").dependOn(&run_cmd.step);

    // Test step
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addImport("libzmx", zmx.module("zmx"));
    test_mod.addImport("zmx", zmx.module("zmx"));

    const tests = b.addTest(.{ .root_module = test_mod });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);

    // Check step (for ZLS / editor diagnostics)
    const check_exe = b.addExecutable(.{
        .name = "zmosh-check",
        .root_module = exe_mod,
    });
    b.step("check", "Check if zmosh compiles").dependOn(&check_exe.step);
}
