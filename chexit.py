import argparse
import functools
import logging
import ipaddress
import itertools
import json
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument('-c',  '--config')
parser.add_argument('-o',  '--output', default=sys.stdout)
parser.add_argument('-v',  '--verbose', action='count', default=0)
parser.add_argument('-e',  '--expand', choices=['addr', 'none'], default='addr')
parser.add_argument('-f',  '--formatter', choices=['json', 'csv'], default='json')
group = parser.add_mutually_exclusive_group()
group.add_argument('-u',  '--uuid',    help='uuid1[:uuid2...]')
group.add_argument('-vp', '--v_polid', help='vdom1,polID1[:vdom2,polID2...]')
args = parser.parse_args()

if args.verbose>0:
    FORMAT = '%(levelname)s:%(message)s'
    LEVEL  = logging.DEBUG
else:
    FORMAT = '%(message)s'
    LEVEL  = logging.INFO

if args.output==sys.stdout:
    logging.basicConfig(stream=args.output,   format=FORMAT, level=LEVEL)
else:
    logging.basicConfig(filename=args.output, filemode='w',
                        format=FORMAT,        level=LEVEL)

def is_match (_match):
    return isinstance(_match, re.Match)

def pipe(args, *funcs):
    return functools.reduce(lambda arg, func: func(arg), funcs, args)

def search_by_uuid(state, line):
    entry = re.sub('\n', '|', line)
    start = r"^\s*edit\s\d+"
    end   = r"^\s*next"

    is_start = lambda: is_match(re.match(start, entry))
    is_end   = lambda: is_match(re.match(end, entry))
    is_found = lambda: is_match(re.search(state['keys'], state['search']))

    match (is_start(), is_found(), is_end()):
        case (True, _, _):
            state['search'] = entry
        case (_, True, True):
            state['found'] = ''.join([state['search'], entry])
            logging.debug('Found {}'.format(state['keys']))
        case _:
            state['search'] = ''.join([state['search'], entry])

    return state

def search_by_v_polid(state, line):
    entry    = re.sub('\n', '|', line)
    pol_id = state['keys'].split(',')[1]
    vdom   = state['keys'].split(',')[0]

    in_global   = lambda: is_match(re.match(r"^\s*config global", entry))
    in_vdom     = lambda: is_match(re.match(r"^\s*edit\s" + vdom, entry))
    in_policy   = lambda: is_match(re.match(r"^\s*edit\s{}[^\d]".format(pol_id), entry))
    in_policies = lambda: is_match(re.match(r"^\s*config firewall policy", entry))

    state['flag'] = {
        ''             : 'Waiting VDOM' if in_global()   else '',
        'Waiting VDOM' : 'In VDOM'      if in_vdom()     else state['flag'],
        'In VDOM'      : 'In policies'  if in_policies() else state['flag'],
        'In policies'  : state['flag']
    }[state.get('flag', '')]

    if re.match(r"^\s*edit\s{}[^\d]".format(pol_id), entry) \
         and state['flag']=='In policies':
        state['search'] = entry
    elif re.match(r"^\s*next", entry) \
         and re.search(pol_id, state['search']):
        state['found'] = ''.join([state['search'], entry])
        dbg = 'Found ID {} in VDOM {}'.format(pol_id, vdom)
        logging.debug(dbg)
    elif state['search'] and state['flag']=='In policies':
        state['search'] = ''.join([state['search'], entry])

    return state

def search_addr_grp(state, line):
    entry = re.sub('\n', '|', line)

    is_subnet  = lambda: is_match(re.search(r"set subnet (.*)\|$", state['search']))
    is_addrgrp = lambda: is_match(re.search(r"set member (.*)\|$", state['search']))

    if state["key"] == 'all':
        state['found'] = {'subnet' : 'all'}
        logging.debug("Found subnet {}".format(state['found']))
    elif re.search('edit "{}"'.format(state["key"]), entry):
        state['search'] = entry
        state['flag'] = 'In address group'
    elif re.search(r"\s*next", entry) and state['flag']=="In address group":
        match (is_subnet(), is_addrgrp()):
            case (True, _):
                match_ = re.search(r"set subnet (.*)\|$", state['search'])
                state['found'] = {'subnet' : match_.group(1)}
                logging.debug("{} : {}".format(state['key'], state['found']))
            case (_, True):
                match_ = re.search(r"set member (.*)\|$", state['search'])
                state['found'] = {'member' : match_.group(1)}
                logging.debug("{} : {}".format(state['key'], state['found']))
    else:
        state['search'] = ''.join([state['search'], entry])

    return state

def fill(info, field):
    return info | dict([split_key_val_in_field(field)])

def trim_keys(found):
    return functools.reduce(fill, found.split('|'), {})

def split_field(field):
    match = re.search(r'^(\w+) (.*)$', field)
    key, val = match.groups()

    return (key, val) if key!='id' else (key, int(val))

def split_key_val_in_field(field):
    key, *value = re.split(' ', field)
    cond = not re.match('^(id|name|action|logtraffic|uuid|comments)', field)

    return (key, value) if cond else split_field(field)

def trim_prfx(found):
    trimmer = lambda STR, RGX: re.sub(RGX[0], RGX[1], STR)
    keyset  = [
        (r'^\s+edit\s(?=\w+)', 'id '),
        (r'(?<=\|)\s+set\s',   ''),
        (r'\|\s+next.*$', ''),
        ('"', '')
    ]

    return functools.reduce(trimmer, keyset, found)

def lookup_key(config_name, key, search_by):
    init = {
        'found'  : '',
        'search' : '',
        'keys'   : key,
        'flag'   : ''
    }

    logging.debug('Looking up {}'.format(key))

    with open(config_name) as config:
        return pipe(
            itertools.accumulate(config, search_by(), initial=init),
            lambda srch: itertools.takewhile(lambda o: not o['found'], srch),
            lambda findings: list(findings).pop()['found']
        )

def add_addr_grp_to_search_or_get_subnet(init, addr):
    addrs, subnets = init
    init_srch = {
        'found'  : '',
        'search' : '',
        'key'    : addrs.pop(0),
        'flag'   : ''
    }

    with open(args.config) as config:
        temp = pipe(
            itertools.accumulate(config, search_addr_grp, initial=init_srch),
            lambda srch: itertools.takewhile(lambda o: not o['found'], srch),
            lambda findings: list(findings).pop()['found']
        )

    match temp:
        case {'subnet' : 'all'}:
            subnets.append('all')
        case {'subnet' : subnet}:
            ip_subnet = ipaddress.ip_network(subnet.replace(" ", "/"))
            subnets.append(str(ip_subnet))
        case {'member' : members}:
            [addrs.append(member.strip('"')) for member in members.split(" ")]

    return (addrs, subnets)

def search_till_subnet_is_found(old_addr_queue, old_subnet_list):
    match len(old_addr_queue):
        case 0:
            return old_subnet_list
        case _:
            length = range(len(old_addr_queue))
            init   = (old_addr_queue, old_subnet_list)
            new_addr_queue, new_subnet_list = functools.reduce(
                add_addr_grp_to_search_or_get_subnet,
                length,
                init
            )

            return search_till_subnet_is_found(
                new_addr_queue,
                new_subnet_list
            )

def expand_subnet_from_addr_grp(output):
    match args.expand:
        case 'none':
            logging.debug("No subnet expansion")
            expansion = {}
        case 'addr':
            logging.debug("Subnet expansion")
            expansion = {
                'srcaddr' : search_till_subnet_is_found(output.get('srcaddr'), []),
                'dstaddr' : search_till_subnet_is_found(output.get('dstaddr'), [])
            }

    return output | expansion

def lookup_keys(config_name, _type, key_list, list_sep=':'):
    def pipe_flow(key):
        return pipe(
            lookup_key(config_name, key, search_by),
            trim_prfx,
            trim_keys,
            expand_subnet_from_addr_grp,
        )

    def search_by():
        return {
            'UUID'           : search_by_uuid,
            'VDOM-AND-POLID' : search_by_v_polid
        }[_type]

    keys = key_list.split(list_sep)
    logging.debug('Number of input, {}: {}'.format(len(keys), keys))

    return [pipe_flow(key) for key in keys]

def format_output(entries, formatter, line_sep=';'):
    def dict_to_string(line, item):
        key, value = item

        match key:
            case 'id':
                return str(value)
            case 'name' | 'uuid' | 'action' | 'logtraffic' | 'comments':
                return line_sep.join([line, value])
            case 'srcintf' | 'dstintf' | 'srcaddr' | 'dstaddr' | \
                 'schedule' | 'service':
                joinedvalues = ','.join(value)
                return line_sep.join([line, joinedvalues])

    match formatter:
        case "json":
            return  pipe(
                entries,
                json.dumps,
                logging.info
            )
        case "csv":
            rows   = [functools.reduce(dict_to_string, entry.items(), '')
                      for entry in entries]
            head   = line_sep.join(entries.pop(0).keys())
            output = ['sep=' + line_sep] + [head] + rows

            return pipe(
                '\n'.join(output),
                logging.info
            )

if __name__ == "__main__":

    if sys.hexversion < 50856688:
        run = '.'.join(map(str, sys.version_info[:3]))
        err = 'chexit requires at least Python 3.8.2; you have {}'.format(run)
        raise RuntimeError(err)

    if args.uuid:
        _type = 'UUID'
        keys  = args.uuid
    elif args.v_polid:
        _type = 'VDOM-AND-POLID'
        keys  = args.v_polid

    pipe(
        lookup_keys(args.config, _type, keys),
        lambda output: format_output(output, args.formatter),
    )
