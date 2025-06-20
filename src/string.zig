//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const mem = std.mem;

pub export fn contains(haystack: [*:0]const u8, needle: [*:0]const u8) bool {
    return if (mem.indexOf(u8, mem.span(haystack), mem.span(needle)) == null) false else true;
}

pub export fn extract_member(string: [*:0]const u8) [*]const u8 {
    return extract_element(string, "set member ");
}

pub export fn extract_subnet(string: [*:0]const u8) [*]const u8 {
    return extract_element(string, "set subnet ");
}

fn extract_element(string: [*:0]const u8, marker: []const u8) [*]const u8 {
    const trimmed = mem.trimLeft(u8, mem.span(string), " \t");
    const index = mem.indexOf(u8, marker, trimmed).? + marker.len;

    return trimmed[index..].ptr;
}
