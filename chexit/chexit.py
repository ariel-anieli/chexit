import argparse
import logging
import ipaddress
import itertools as it
import json
import os
import re
import sys

from functools import reduce
from cffi import FFI

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--config")
parser.add_argument("-o", "--output", default=sys.stdout)
parser.add_argument("-v", "--verbose", action="count", default=0)
parser.add_argument("-e", "--expand", choices=["addr", "none"], default="addr")
parser.add_argument("-f", "--formatter", choices=["json", "csv"], default="json")
group = parser.add_mutually_exclusive_group()
group.add_argument("-u", "--uuid", help="uuid1[:uuid2...]")
group.add_argument("-vp", "--v_polid", help="vdom1,polID1[:vdom2,polID2...]")
args = parser.parse_args()

if args.verbose > 0:
    FORMAT = "%(levelname)s:%(message)s"
    LEVEL = logging.DEBUG
else:
    FORMAT = "%(message)s"
    LEVEL = logging.INFO

if args.output == sys.stdout:
    logging.basicConfig(stream=args.output, format=FORMAT, level=LEVEL)
else:
    logging.basicConfig(filename=args.output, filemode="w", format=FORMAT, level=LEVEL)

# FFI
cffi = FFI()
cffi.cdef("""
char* expand_subnet_from_addr_grp(char* output, char* expander, char* filename);
char* search_by_uuid(char* state, char* line);
char* search_by_v_polid(char* state, char* line);
char* trim_prfx(char* found);
char* trim_keys(char* found);
""")
dll = cffi.dlopen(os.path.abspath("util.so"))


def is_match(_match):
    return isinstance(_match, re.Match)


def pipe(args, *funcs):
    return reduce(lambda arg, func: func(arg), funcs, args)


def search_by_uuid(state, line):
    return json.loads(
        cffi.string(
            dll.search_by_uuid(json.dumps(state).encode(), line.encode())
        ).decode("utf-8")
    )


def search_by_v_polid(state, line):
    return json.loads(
        cffi.string(
            dll.search_by_v_polid(json.dumps(state).encode(), line.encode())
        ).decode("utf-8")
    )


def trim_keys(found):
    return json.loads(cffi.string(dll.trim_keys(found.encode())).decode("utf-8"))


def trim_prfx(found):
    return cffi.string(dll.trim_prfx(found.encode())).decode("utf-8")


def lookup_key(config_name, key, search_by):
    init = {"found": "", "search": "", "keys": key, "flag": ""}
    default = {"found": ""}

    logging.debug(f"Looking up {key}")

    with open(config_name) as config:
        all_results = it.accumulate(config, search_by(), initial=init)
        search_result = next(filter(lambda o: o.get("found"), all_results), default)

    return search_result["found"]


def expand_subnet_from_addr_grp(output):
    return json.loads(
        cffi.string(
            dll.expand_subnet_from_addr_grp(
                json.dumps(output).encode(), args.expand.encode(), args.config.encode()
            )
        ).decode("utf-8")
    )


def lookup_keys(config_name, _type, key_list, list_sep=":"):
    def pipe_flow(key):
        return pipe(
            lookup_key(config_name, key, search_by),
            trim_prfx,
            trim_keys,
            expand_subnet_from_addr_grp,
        )

    def search_by():
        return {"UUID": search_by_uuid, "VDOM-AND-POLID": search_by_v_polid}[_type]

    keys = key_list.split(list_sep)
    logging.debug(f"Number of input, {len(keys)}: {keys}")

    return [pipe_flow(key) for key in keys]


def format_output(entries, formatter, line_sep=";"):
    def dict_to_string(line, item):
        key, value = item

        match key:
            case "id":
                return str(value)
            case "name" | "uuid" | "action" | "logtraffic" | "comments":
                return f"{line}{line_sep}{value}"
            case "srcintf" | "dstintf" | "srcaddr" | "dstaddr" | "schedule" | "service":
                joinedvalues = ",".join(value)
                return f"{line}{line_sep}{joinedvalues}"

    match formatter:
        case "json":
            return pipe(entries, json.dumps, logging.info)
        case "csv":
            rows = [reduce(dict_to_string, entry.items(), "") for entry in entries]
            head = line_sep.join(entries.pop(0).keys())
            output = ["sep=" + line_sep] + [head] + rows

            return pipe("\n".join(output), logging.info)


if __name__ == "__main__":
    if args.uuid:
        _type = "UUID"
        keys = args.uuid
    elif args.v_polid:
        _type = "VDOM-AND-POLID"
        keys = args.v_polid

    pipe(
        lookup_keys(args.config, _type, keys),
        lambda output: format_output(output, args.formatter),
    )

    cffi.dlclose(dll)
