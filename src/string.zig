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

pub export fn extract_member(string: [*]const u8) [*]const u8 {
    return extract_element(string, "set member ");
}

pub export fn extract_subnet(string: [*]const u8) [*]const u8 {
    return extract_element(string, "set subnet ");
}

fn extract_element(string: [*]const u8, marker: []const u8) [*]const u8 {
    const string_nt: [*:0]const u8 = @ptrCast(string);
    const string_slice: []const u8 = std.mem.span(string_nt);

    const trimmed_slice = std.mem.trimLeft(u8, string_slice, " \t");
    const index = std.mem.indexOf(u8, marker, trimmed_slice).? + marker.len;

    return trimmed_slice[index..].ptr;
}
