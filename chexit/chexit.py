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
char* add_addr_grp_to_search_or_get_subnet(char* filename, char* key);
char* search_by_uuid(char* state, char* line);
char* trim_prfx(char* found);
char* trim_keys(char* found);
""")
dll = cffi.dlopen(os.path.abspath("util.so"))


def is_match(_match):
    return isinstance(_match, re.Match)


def pipe(args, *funcs):
    return reduce(lambda arg, func: func(arg), funcs, args)


def search_by_uuid(state, line):
    entry = line.replace("\n", "|")

    if re.match(r"^\s*edit\s\d+", entry) is not None:
        state["Search"] = entry
    elif (
        re.match(r"^\s*next", entry) is not None
        and re.search(state["Keys"], state["Search"]) is not None
    ):
        state["Found"] = f"{state['Search']}{entry}"
        logging.debug(f"Found {state['Keys']}")
    else:
        state["Search"] = f"{state['Search']}{entry}"

    return state


def search_by_v_polid(state, line):
    entry = re.sub("\n", "|", line)
    pol_id = state["Keys"].split(",")[1]
    vdom = state["Keys"].split(",")[0]

    in_global = lambda: is_match(re.match(r"^\s*config global", entry))
    in_vdom = lambda: is_match(re.match(r"^\s*edit\s" + vdom, entry))
    in_policy = lambda: is_match(re.match(rf"^\s*edit\s{pol_id}[^\d]", entry))
    in_policies = lambda: is_match(re.match(r"^\s*config firewall policy", entry))

    state["Flag"] = {
        "": "Waiting VDOM" if in_global() else "",
        "Waiting VDOM": "In VDOM" if in_vdom() else state["Flag"],
        "In VDOM": "In policies" if in_policies() else state["Flag"],
        "In policies": state["Flag"],
    }[state.get("Flag", "")]

    if re.match(rf"^\s*edit\s{pol_id}[^\d]", entry) and state["Flag"] == "In policies":
        state["Search"] = entry
    elif re.match(r"^\s*next", entry) and re.search(pol_id, state["Search"]):
        state["Found"] = f"{state['Search']}{entry}"
        dbg = f"Found ID {pol_id} in VDOM {vdom}"
        logging.debug(dbg)
    elif state["Search"] and state["Flag"] == "In policies":
        state["Search"] = f"{state['Search']}{entry}"

    return state


def trim_keys(found):
    return json.loads(cffi.string(dll.trim_keys(found.encode())).decode("utf-8"))


def trim_prfx(found):
    return cffi.string(dll.trim_prfx(found.encode())).decode("utf-8")


def lookup_key(config_name, key, search_by):
    init = {"Found": "", "Search": "", "Keys": key, "Flag": ""}
    default = {"Found": ""}

    logging.debug(f"Looking up {key}")

    with open(config_name) as config:
        all_results = it.accumulate(config, search_by(), initial=init)
        search_result = next(filter(lambda o: o.get("Found"), all_results), default)

    return search_result["Found"]


def add_addr_grp_to_search_or_get_subnet(init, _):
    old_addrs, subnets = init
    key, *new_addrs = old_addrs

    match json.loads(
        cffi.string(
            dll.add_addr_grp_to_search_or_get_subnet(args.config.encode(), key.encode())
        ).decode("utf-8")
    ):
        case {"subnet": "all"}:
            subnets.add("all")
        case {"subnet": subnet}:
            ip_subnet = ipaddress.ip_network(subnet.replace(" ", "/"))
            subnets.add(str(ip_subnet))
        case {"member": members}:
            new_addrs.extend(member.strip('"') for member in members.split(" "))
        case "":
            subnets.union(set())

    return (new_addrs, subnets)


def search_till_subnet_is_found(old_addrs, old_subnets):
    if not len(old_addrs):
        return list(old_subnets)

    init = (old_addrs, old_subnets)
    new_addrs, new_subnets = reduce(
        add_addr_grp_to_search_or_get_subnet, range(len(old_addrs)), init
    )

    return search_till_subnet_is_found(new_addrs, new_subnets)


def expand_subnet_from_addr_grp(output):
    match args.expand:
        case "none":
            logging.debug("No subnet expansion")
            expansion = {}
        case "addr":
            logging.debug("Subnet expansion")
            expansion = {
                "srcaddr": search_till_subnet_is_found(output.get("srcaddr"), set()),
                "dstaddr": search_till_subnet_is_found(output.get("dstaddr"), set()),
            }

    return output | expansion


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
    if sys.hexversion < 50856688:
        run = ".".join(map(str, sys.version_info[:3]))
        err = f"chexit requires at least Python 3.8.2; you have {run}"
        raise RuntimeError(err)

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
