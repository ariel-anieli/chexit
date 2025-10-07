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
char* lookup_key(char* lookup);
""")
dll = cffi.dlopen(os.path.abspath("util.so"))


def pipe(args, *funcs):
    return reduce(lambda arg, func: func(arg), funcs, args)


def lookup_key(config_name, key, search_by):
    return json.loads(
        cffi.string(
            dll.lookup_key(
                json.dumps(
                    {
                        "filename": config_name,
                        "key": key,
                        "search-by": search_by,
                        "expander": args.expand,
                    }
                ).encode()
            )
        ).decode("utf-8")
    )


def lookup_keys(config_name, _type, key_list, list_sep=":"):
    keys = key_list.split(list_sep)
    logging.debug(f"Number of input, {len(keys)}: {keys}")

    return [lookup_key(config_name, key, _type) for key in keys]


def format_output(entries, formatter, line_sep=";"):
    def dict_to_string(line, item):
        key, value = item

        if key == "id":
            return str(value)
        elif key in {"name", "uuid", "action", "logtraffic", "comments"}:
            return f"{line}{line_sep}{value}"
        elif key in {"srcintf", "dstintf", "srcaddr", "dstaddr", "schedule", "service"}:
            return f"{line}{line_sep}" + ",".join(value)

    if formatter == "json":
        return pipe(entries, json.dumps, logging.info)
    elif formatter == "csv":
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

    format_output(lookup_keys(args.config, _type, keys), args.formatter)

    cffi.dlclose(dll)
