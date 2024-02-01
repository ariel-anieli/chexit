import argparse
import functools
import logging
import itertools
import json
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument('-c',  '--config')
parser.add_argument('-o',  '--output', default=sys.stdout)
parser.add_argument('-v',  '--verbose', action='count', default=0)
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

def pipe(args, *funcs):
    return functools.reduce(lambda arg, func: func(arg), funcs, args)

def look_up_all_keys_of_type_into(cfg, key_type, key_list, list_sep=':'):

    def search_by_uuid(state, line):
        entry = re.sub('\n', '|', line)
        start = "^\s*edit\s\d+"
        end   = "^\s*next"

        if re.match(start, entry):
            state['search'] = entry
        elif re.match(end, entry) and re.search(state['keys'], state['search']):
            state['found'] = ''.join([state['search'], entry])
            logging.debug('Found {}'.format(state['keys']))
        else:
            state['search'] = ''.join([state['search'], entry])

        return state

    def search_by_v_polid(state, line):
        entry    = re.sub('\n', '|', line)
        pol_id = state['keys'].split(',')[1]
        vdom   = state['keys'].split(',')[0]

        if re.match("^\s*config global", entry):
            state['flag'] = 'Waiting VDOM'
        elif re.match("^\s*edit\s" + vdom, entry) \
             and state['flag']=='Waiting VDOM':
            state['flag'] = 'In VDOM'
        elif re.match("^\s*config firewall policy", entry) \
             and state['flag']=='In VDOM':
            state['flag'] = 'In policies'
        elif re.match("^\s*edit\s{}[^\d]".format(pol_id), entry) \
             and state['flag']=='In policies':
            state['search'] = entry
        elif re.match("^\s*next", entry) \
             and re.search(pol_id, state['search']):
            state['found'] = ''.join([state['search'], entry])
            dbg = 'Found ID {} in VDOM {}'.format(pol_id, vdom)
            logging.debug(dbg)
        elif state['search'] and state['flag']=='In policies':
            state['search'] = ''.join([state['search'], entry])

        return state

    def look_up_each_key_of_type_into(key):
        init      = {'found'  : '',
                     'search' : '',
                     'keys'   : key,
                     'flag'   : ''}

        search_by = lambda: {
            'UUID'           : search_by_uuid,
            'VDOM-AND-POLID' : search_by_v_polid
        }[key_type]

        logging.debug('Looking up {}'.format(key))

        with open(cfg) as conf:
            full_cfg = conf.readlines()

        return pipe(
            itertools.accumulate(full_cfg, search_by(), initial=init),
            lambda search: itertools.takewhile(lambda x: not x['found'], search),
            lambda findings: list(findings).pop()['found']
        )

    def trim_keys(found):
        head  = lambda items: items[0]
        tail  = lambda items: items[1:]
        split = lambda item: re.split(' ', item)

        def fill(info, field):
            if not re.match('^(id|logtraffic|uuid|comments)', field):
                return info | {head(split(field)) : tail(split(field))}
            else:
                match = re.search('^(\w+) (.*)$', field)
                key   = match.group(1)
                value = match.group(2) if key!='id' else int(match.group(2))

                return info | {key : value}

        return functools.reduce(fill, found.split('|'), {})

    def trim_prfx(found):
        trimmer = lambda STR, RGX: re.sub(RGX[0], RGX[1], STR)
        keyset  = [
            ('^\s+edit\s(?=\w+)', 'id '),
            ('(?<=\|)\s+set\s',   ''),
            ('\|\s+next.*$', ''),
            ('"', '')
        ]

        return functools.reduce(trimmer, keyset, found)

    keys = key_list.split(list_sep)
    logging.debug('Number of input, {}: {}'.format(len(keys), keys))

    def pipe_flow(key):
        return pipe(
            key,
            look_up_each_key_of_type_into,
            trim_prfx,
            trim_keys,
            json.dumps,
            logging.info
        )

    [pipe_flow(key) for key in keys]

if __name__ == "__main__":

    if sys.hexversion < 50856688:
        run = '.'.join(map(str, sys.version_info[:3]))
        err = 'chexit requires at least Python 3.8.2; you have {}'.format(run)
        raise RuntimeError(err)

    if args.uuid:
        key_type  = 'UUID'
        key_value = args.uuid
    elif args.v_polid:
        key_type  = 'VDOM-AND-POLID'
        key_value = args.v_polid

    look_up_all_keys_of_type_into(
        args.config,
        key_type,
        key_value
    )
