//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;

pub export fn contains(haystack: [*]const u8, needle: [*]const u8) bool {
    const haystack_nt: [*:0]const u8 = @ptrCast(haystack);
    const needle_nt: [*:0]const u8 = @ptrCast(needle);

    const haystack_slice: []const u8 = std.mem.span(haystack_nt);
    const needle_slice: []const u8 = std.mem.span(needle_nt);

    return if (std.mem.indexOf(u8, haystack_slice, needle_slice) != null) true else false;
}
