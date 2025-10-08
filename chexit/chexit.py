import argparse
import json
import os
import sys

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

# FFI
cffi = FFI()
cffi.cdef("void lookup_keys(char* lookup);")
dll = cffi.dlopen(os.path.abspath("parse.so"))

def lookup_keys(config_name, _type, key_list, list_sep=":"):
    return dll.lookup_keys(
        json.dumps(
            {
                "filename": config_name,
                "keys": key_list,
                "search-by": _type,
                "expander": args.expand,
                "formatter": args.formatter,
            }
        ).encode()
    )


if __name__ == "__main__":
    if args.uuid:
        _type = "UUID"
        keys = args.uuid
    elif args.v_polid:
        _type = "VDOM-AND-POLID"
        keys = args.v_polid

    lookup_keys(args.config, _type, keys)

    cffi.dlclose(dll)
