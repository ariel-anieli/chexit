'''Using a FortiGate configuration, checks a policy, and exits it in CSV.'''

import argparse
import functools
import logging
import itertools
import re
import sys

from typing import List

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

def tell_accepted_types() -> List[str]:
    return ['UUID', 'VDOM-AND-POLID']
    

def look_up_all_keys_of_type_into(
        cfg      : str,
        key_type : str,
        key_list : str,
        list_sep = ':') -> str:

    def build_csv_row(trimmed: List[str]) -> str:
        return '|'.join(trimmed)

    def search_by_uuid(state: dict, line: str) -> dict:
        in_ = re.sub('\n', '|', line)
        if re.match("^\s*edit\s\d+", in_):
            state['search'] = in_
        elif re.match("^\s*next", in_) \
             and re.search(state['keys'], state['search']):
            state['found'] = ''.join([state['search'], in_])
            logging.debug('Found {}'.format(state['keys']))
        else:
            state['search'] = ''.join([state['search'], in_])

        return state

    def search_by_v_polid(state: dict, line: str) -> dict:
        in_    = re.sub('\n', '|', line)
        pol_id = state['keys'].split(',')[1]
        vdom   = state['keys'].split(',')[0]

        if re.match("^\s*config global", in_):
            state['flag'] = 'Waiting VDOM'
        elif re.match("^\s*edit\s" + vdom, in_) \
             and state['flag']=='Waiting VDOM':
            state['flag'] = 'In VDOM'
        elif re.match("^\s*config firewall policy", in_) \
             and state['flag']=='In VDOM':
            state['flag'] = 'In policies'
        elif re.match("^\s*edit\s{}[^\d]".format(pol_id), in_) \
             and state['flag']=='In policies':
            state['search'] = in_
        elif re.match("^\s*next", in_) \
             and re.search(pol_id, state['search']):
            state['found'] = ''.join([state['search'], in_])
            dbg = 'Found ID {} in VDOM {}'.format(pol_id, vdom)
            logging.debug(dbg)
        elif state['search'] and state['flag']=='In policies':
            state['search'] = ''.join([state['search'], in_])

        return state

    def look_up_each_key_of_type_into(key: str) -> str:

        init = {'found'  : '',
                'search' : '',
                'keys'   : key,
                'flag'   : ''}

        search_by = search_by_uuid if key_type=='UUID' \
            else search_by_v_polid if key_type=='VDOM-AND-POLID' \
            else None

        logging.debug('Looking up {}'.format(key))

        with open(cfg) as conf:
            full_cfg = conf.readlines()

            return list(itertools.takewhile(lambda x: not x['found'],
                                            itertools.accumulate(full_cfg,
                                                                 search_by,
                                                                 initial=init))).pop()['found']

    def trim_keys(trim_prfx: str) -> str:

        return [re.sub('^\w+ ', '', FLD)
                for FLD in trim_prfx.split('|')
                if re.match('^(uuid|src|dst|service|\d+)', FLD)
                and not re.match('^\w+\-', FLD)]

    def trim_prfx(found: str) -> str:
        return functools.reduce(lambda STR, RGX: re.sub(RGX[0], RGX[1], STR),
                                [('^\s+edit\s(?=\w+)', ''),
                                 ('(?<=\|)\s+set\s',   '')], found)

    keys = key_list.split(list_sep)
    logging.debug('Number of input, {}: {}'.format(len(keys), keys))

    [functools.reduce(lambda _IN, FUNC: FUNC(_IN),
                      [look_up_each_key_of_type_into,
                       trim_prfx,
                       trim_keys,
                       build_csv_row,
                       logging.info],
                      OBJ) for OBJ in keys]

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

    HEAD = '|'.join(
        ['id',
         'uuid',
         'srcintf',
         'dstintf',
         'srcaddr',
         'dstaddr',
         'service']
    )

    logging.info(HEAD)

    look_up_all_keys_of_type_into(
        args.config,
        key_type,
        key_value
    )
