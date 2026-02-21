const std = @import("std");

const linux_targets: []const std.Target.Query = &.{
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
};

const macos_targets: []const std.Target.Query = &.{
    .{ .cpu_arch = .x86_64, .os_tag = .macos },
    .{ .cpu_arch = .aarch64, .os_tag = .macos },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_msquic = b.option(bool, "enable_msquic", "Enable experimental QUIC transport via MsQuic C API") orelse false;
    const msquic_include_dir = b.option([]const u8, "msquic_include_dir", "Path to directory containing msquic.h");
    const msquic_lib_dir = b.option([]const u8, "msquic_lib_dir", "Path to directory containing libmsquic");
    const version = b.option([]const u8, "version", "Version string for release") orelse
        @as([]const u8, @import("build.zig.zon").version);

    const run_step = b.step("run", "Run the app");
    const test_step = b.step("test", "Run unit tests");

    var code: u8 = 0;
    const git_sha = std.mem.trim(u8, b.runAllowFail(
        &.{ "git", "rev-parse", "--short", "HEAD" },
        &code,
        .Inherit,
    ) catch "unknown", "\n");

    const options = b.addOptions();
    options.addOption([]const u8, "version", version);
    options.addOption([]const u8, "git_sha", git_sha);
    options.addOption([]const u8, "ghostty_version", @import("build.zig.zon").dependencies.ghostty.hash);
    options.addOption(bool, "enable_msquic", enable_msquic);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    configureMsquicModule(exe_mod, msquic_include_dir);
    exe_mod.addOptions("build_options", options);

    // You'll want to use a lazy dependency here so that ghostty is only
    // downloaded if you actually need it.
    if (b.lazyDependency("ghostty", .{
        .target = target,
        .optimize = optimize,
    })) |dep| {
        exe_mod.addImport(
            "ghostty-vt",
            dep.module("ghostty-vt"),
        );
    }

    // Exe
    const exe = b.addExecutable(.{
        .name = "zmosh",
        .root_module = exe_mod,
    });
    configureMsquicLink(exe, enable_msquic, msquic_lib_dir);
    exe.linkLibC();

    b.installArtifact(exe);

    // Run
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    // Test
    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    configureMsquicLink(exe_unit_tests, enable_msquic, msquic_lib_dir);
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    test_step.dependOn(&run_exe_unit_tests.step);

    // This is where the interesting part begins.
    // As you can see we are re-defining the same executable but
    // we're binding it to a dedicated build step.
    const exe_check = b.addExecutable(.{
        .name = "zmosh",
        .root_module = exe_mod,
    });
    configureMsquicLink(exe_check, enable_msquic, msquic_lib_dir);
    exe_check.linkLibC();
    // There is no `b.installArtifact(exe_check);` here.

    // Finally we add the "check" step which will be detected
    // by ZLS and automatically enable Build-On-Save.
    // If you copy this into your `build.zig`, make sure to rename 'foo'
    const check = b.step("check", "Check if foo compiles");
    check.dependOn(&exe_check.step);

    // Release step - macOS can cross-compile to Linux, but Linux cannot cross-compile to macOS (needs SDK)
    const native_os = @import("builtin").os.tag;
    const release_targets = if (native_os == .macos) linux_targets ++ macos_targets else linux_targets;
    const release_step = b.step("release", "Build release binaries (macOS builds all, Linux builds Linux only)");
    for (release_targets) |release_target| {
        const resolved = b.resolveTargetQuery(release_target);
        const release_mod = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = resolved,
            .optimize = .ReleaseSafe,
        });
        configureMsquicModule(release_mod, msquic_include_dir);
        release_mod.addOptions("build_options", options);

        if (b.lazyDependency("ghostty", .{
            .target = resolved,
            .optimize = .ReleaseSafe,
        })) |dep| {
            release_mod.addImport("ghostty-vt", dep.module("ghostty-vt"));
        }

        const release_exe = b.addExecutable(.{
            .name = "zmosh",
            .root_module = release_mod,
        });
        configureMsquicLink(release_exe, enable_msquic, msquic_lib_dir);
        release_exe.linkLibC();

        const os_name = @tagName(release_target.os_tag orelse .linux);
        const arch_name = @tagName(release_target.cpu_arch orelse .x86_64);
        const tarball_name = b.fmt("zmosh-{s}-{s}-{s}.tar.gz", .{ version, os_name, arch_name });

        const tar = b.addSystemCommand(&.{ "tar", "--no-xattrs", "-czf" });

        const tarball = tar.addOutputFileArg(tarball_name);
        tar.addArg("-C");
        tar.addDirectoryArg(release_exe.getEmittedBinDirectory());
        tar.addArg("zmosh");

        const shasum = b.addSystemCommand(&.{ "shasum", "-a", "256" });
        shasum.addFileArg(tarball);
        const shasum_output = shasum.captureStdOut();

        const install_tar = b.addInstallFile(tarball, b.fmt("dist/{s}", .{tarball_name}));
        const install_sha = b.addInstallFile(shasum_output, b.fmt("dist/{s}.sha256", .{tarball_name}));
        release_step.dependOn(&install_tar.step);
        release_step.dependOn(&install_sha.step);
    }

    // Upload step - rsync docs and dist to pgs.sh
    const upload_step = b.step("upload", "Upload docs and dist to pgs.sh:/zmx");

    const rsync_docs = b.addSystemCommand(&.{ "rsync", "-rv", "docs/", "pgs.sh:/zmx" });
    const rsync_dist = b.addSystemCommand(&.{ "rsync", "-rv", "zig-out/dist/", "pgs.sh:/zmx/a" });

    upload_step.dependOn(&rsync_docs.step);
    upload_step.dependOn(&rsync_dist.step);

    // -----------------------------------------------------------------------
    // Library targets (libzmosh)
    // -----------------------------------------------------------------------

    // `zig build lib` — static library for the host target (dev/testing)
    {
        const lib_step = b.step("lib", "Build libzmosh static library for host");
        const lib_mod = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
        });
        const lib = b.addLibrary(.{
            .name = "zmosh",
            .root_module = lib_mod,
        });
        lib.bundle_compiler_rt = true;
        const install_lib = b.addInstallArtifact(lib, .{});
        const install_header = b.addInstallFile(b.path("include/zmosh/zmosh.h"), "include/zmosh/zmosh.h");
        lib_step.dependOn(&install_lib.step);
        lib_step.dependOn(&install_header.step);
    }

    // Apple library targets (macOS only)
    if (native_os == .macos) {
        const macos_lib_step = b.step("macos-lib", "Build libzmosh.a for macOS (aarch64)");
        const ios_lib_step = b.step("ios-lib", "Build libzmosh.a for iOS + simulator (aarch64)");
        const xcf_step = b.step("xcframework", "Build zmosh.xcframework (macOS + iOS)");

        // macOS aarch64
        const macos_lib = addLibTarget(b, .{
            .cpu_arch = .aarch64,
            .os_tag = .macos,
            .os_version_min = .{ .semver = .{ .major = 13, .minor = 0, .patch = 0 } },
        });
        const install_macos = b.addInstallFile(macos_lib.getEmittedBin(), "lib/libzmosh-macos.a");
        macos_lib_step.dependOn(&install_macos.step);

        // iOS device aarch64
        const ios_lib = addLibTarget(b, .{
            .cpu_arch = .aarch64,
            .os_tag = .ios,
            .os_version_min = .{ .semver = .{ .major = 15, .minor = 0, .patch = 0 } },
        });

        // iOS simulator aarch64 — pin CPU to apple_a17 to work around Zig bug
        // where the generic CPU model emits unsupported instructions for simulator.
        var sim_query: std.Target.Query = .{
            .cpu_arch = .aarch64,
            .os_tag = .ios,
            .abi = .simulator,
            .os_version_min = .{ .semver = .{ .major = 15, .minor = 0, .patch = 0 } },
        };
        sim_query.cpu_model = .{ .explicit = &std.Target.aarch64.cpu.apple_a17 };
        const sim_lib = addLibTarget(b, sim_query);

        // ios-lib: xcodebuild -create-xcframework with device + simulator
        const ios_xcf = addXCFrameworkCommand(b, "zig-out/zmosh-ios.xcframework", &.{
            .{ .lib = ios_lib, .name = "ios-arm64" },
            .{ .lib = sim_lib, .name = "ios-arm64_simulator" },
        });
        ios_lib_step.dependOn(&ios_xcf.step);

        // xcframework: all three slices (macOS + iOS device + iOS simulator)
        const full_xcf = addXCFrameworkCommand(b, "zig-out/zmosh.xcframework", &.{
            .{ .lib = macos_lib, .name = "macos-arm64" },
            .{ .lib = ios_lib, .name = "ios-arm64" },
            .{ .lib = sim_lib, .name = "ios-arm64_simulator" },
        });
        xcf_step.dependOn(&full_xcf.step);
    }
}

fn configureMsquicModule(mod: *std.Build.Module, include_dir: ?[]const u8) void {
    if (include_dir) |dir| {
        mod.addIncludePath(.{ .cwd_relative = dir });
    }
}

fn configureMsquicLink(step: *std.Build.Step.Compile, enable: bool, lib_dir: ?[]const u8) void {
    if (!enable) return;
    if (lib_dir) |dir| {
        step.addLibraryPath(.{ .cwd_relative = dir });
        step.addRPath(.{ .cwd_relative = dir });
    }
    step.linkSystemLibrary("msquic");
}

/// Create a static library target for lib.zig with the given target query.
fn addLibTarget(b: *std.Build, query: std.Target.Query) *std.Build.Step.Compile {
    const resolved = b.resolveTargetQuery(query);
    const mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = resolved,
        .optimize = .ReleaseSafe,
    });
    const lib = b.addLibrary(.{
        .name = "zmosh",
        .root_module = mod,
    });
    lib.bundle_compiler_rt = true;
    return lib;
}

const LibSlice = struct {
    lib: *std.Build.Step.Compile,
    name: []const u8,
};

/// Assemble a .framework bundle from a static library and headers,
/// then create an xcframework using -framework (not -library).
/// This ensures headers stay isolated inside each framework bundle and
/// don't leak into other modules' header search paths.
fn addXCFrameworkCommand(b: *std.Build, output_path: []const u8, slices: []const LibSlice) *std.Build.Step.Run {
    // rm -rf old framework first
    const rm = b.addSystemCommand(&.{ "rm", "-rf", output_path });

    const xcf = b.addSystemCommand(&.{"xcodebuild"});
    xcf.addArgs(&.{"-create-xcframework"});

    for (slices) |slice| {
        // Create a .framework bundle directory for each slice:
        //   zmosh.framework/
        //     zmosh          (the static library binary)
        //     Headers/
        //       zmosh.h
        //     Info.plist
        const fw_dir = b.fmt("zig-out/fw-{s}/zmosh.framework", .{slice.name});

        // Clean and create the framework directory structure
        const mkdir = b.addSystemCommand(&.{ "sh", "-c", b.fmt(
            "rm -rf zig-out/fw-{s} && mkdir -p {s}/Headers",
            .{ slice.name, fw_dir },
        ) });

        // Copy the static library as the framework binary
        const cp_lib = b.addSystemCommand(&.{"cp"});
        cp_lib.addFileArg(slice.lib.getEmittedBin());
        cp_lib.addArg(b.fmt("{s}/zmosh", .{fw_dir}));
        cp_lib.step.dependOn(&mkdir.step);

        // Copy headers (flatten: zmosh/zmosh.h → zmosh.h)
        const cp_hdr = b.addSystemCommand(&.{ "cp", "include/zmosh/zmosh.h", b.fmt("{s}/Headers/zmosh.h", .{fw_dir}) });
        cp_hdr.step.dependOn(&mkdir.step);

        // Write framework Info.plist
        const write_plist = b.addSystemCommand(&.{
            "sh", "-c", b.fmt(
                \\cat > {s}/Info.plist << 'PLIST'
                \\<?xml version="1.0" encoding="UTF-8"?>
                \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                \\<plist version="1.0">
                \\<dict>
                \\    <key>CFBundleDevelopmentRegion</key>
                \\    <string>en</string>
                \\    <key>CFBundleExecutable</key>
                \\    <string>zmosh</string>
                \\    <key>CFBundleIdentifier</key>
                \\    <string>com.mmonad.zmosh</string>
                \\    <key>CFBundleInfoDictionaryVersion</key>
                \\    <string>6.0</string>
                \\    <key>CFBundleName</key>
                \\    <string>zmosh</string>
                \\    <key>CFBundlePackageType</key>
                \\    <string>FMWK</string>
                \\    <key>CFBundleShortVersionString</key>
                \\    <string>0.1.0</string>
                \\    <key>CFBundleVersion</key>
                \\    <string>1</string>
                \\    <key>MinimumOSVersion</key>
                \\    <string>17.0</string>
                \\</dict>
                \\</plist>
                \\PLIST
            , .{fw_dir}),
        });
        write_plist.step.dependOn(&mkdir.step);

        xcf.addArg("-framework");
        xcf.addArg(fw_dir);
        xcf.step.dependOn(&cp_lib.step);
        xcf.step.dependOn(&cp_hdr.step);
        xcf.step.dependOn(&write_plist.step);
    }

    xcf.addArgs(&.{ "-output", output_path });
    xcf.step.dependOn(&rm.step);
    return xcf;
}
