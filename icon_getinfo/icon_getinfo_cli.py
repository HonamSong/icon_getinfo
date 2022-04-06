#!/usr/bin/env python3
# -*- coding: utf-8 -*-

try:
    from .__version__ import __version__
except:
    from __version__ import __version__

import time
from icon_getinfo import *
from icon_getinfo import IconNodeGetInfo as Ig


def print_banner(args):
    banner = """
    starting to IconNetwork Node Information !!
     _   _           _        ___        __
    | \ | | ___   __| | ___  |_ _|_ __  / _| ___
    |  \| |/ _ \ / _` |/ _ \  | || '_ \| |_ / _ \\
    | |\  | (_) | (_| |  __/  | || | | |  _| (_) |
    |_| \_|\___/ \__,_|\___| |___|_| |_|_|  \___/

    """

    for line in banner.split('\n'):
        cprint(f'{line}', 'green')

    cprint(f'    + {"version":20} : {__version__}', 'green')
    cprint(f'    + {"Running Data":20} : {todaydate("ms")}', 'green')
    cprint(f'    + {"Input Check node ip":20} : {args.url}\n\n', 'green')


def parse_args(**kwargs):
    import argparse
    parser = argparse.ArgumentParser(description="Get icon node information")
    parser.add_argument('mode', default='chain', help=f'Icon Network get information mode',
                        choices=['chain', 'chain_detail', 'chain_inspect', 'system', 'all', 'all_chain',
                                 'all_chain_inspect', 'all_chain_detail', 'all_system', 'all_node'])
    parser.add_argument("-u", "--url", default="http://localhost")
    parser.add_argument("-v", "--version", action='store_true', help='Show Version')
    parser.add_argument("--duration_time", action='store_true', help='Show Duration of time')
    parser.add_argument("--notrunc", action='store_true', help="Don't truncate output", dest='notrunc')
    parser.add_argument("--showlog", action='store_true', help='Show running log')
    parser.add_argument("--filter", "-f", nargs='+', help='Out put print filter', default=None, dest='filter')

    return parser.parse_args()


def main_run(get_node, mode, notrunc):
    print_title = None
    field_name = None
    field_data = None
    noti_str1 = 'Icon Network Node'
    noti_str2 = 'Icon Network All Node'

    if mode == 'chain':
        res_json, field_name, field_data = get_node.get_node(get_local=True, get_chain=True, no_trunc=notrunc)
        print_title = f'< {noti_str1} Default information >'

    if mode == 'chain_detail' or mode == "chain_inspect":
        res_json, field_name, field_data = get_node.get_node(get_local=True, get_inspect=True, no_trunc=notrunc)
        print_title = f'< {noti_str1} Detail information >'

    if mode == 'system':
        res_json, field_name, field_data = get_node.get_node(get_local=True, get_system=True, no_trunc=notrunc)
        print_title = f'< {noti_str1} System information >'

    if mode == 'all':
        res_json, field_name, field_data = get_node.get_node(get_local=True, get_all=True, no_trunc=notrunc)
        print_title = f'< {noti_str1} All information >'

    if mode == 'all_chain':
        field_name, field_data = get_node.get_all_node(get_type='chain', no_trunc=notrunc)
        print_title = f'< {noti_str2} Chain default information >'

    if mode == 'all_chain_inspect' or mode == 'all_chain_detail':
        field_name, field_data = get_node.get_all_node(get_type='chain_inspect', no_trunc=notrunc)
        print_title = f'< {noti_str2} Chain Detail information >'

    if mode == 'all_system':
        field_name, field_data = get_node.get_all_node(get_type='system', no_trunc=notrunc)
        print_title = f'< {noti_str2} System information >'

    if mode == 'all_node':
        field_name, field_data = get_node.get_all_node(get_type='all', no_trunc=notrunc)
        print_title = f'< {noti_str2} information >'

    return print_title, field_name, field_data


def main():
    start_time = time.time()
    disable_ssl_warnings()

    print_title = None
    field_name = None
    field_data = None

    args = parse_args()

    if args.version:
        cprint(f'version : {__version__}')
        sys.exit(0)

    print_banner(args)

    get_node = Ig(url=args.url, showlog=args.showlog)

    if len(sys.argv) == 1:
        print(json.dumps(get_node.get_node(get_local=True, get_chain=True), indent=4))
    else:
        print_title, field_name, field_data = main_run(get_node, args.mode, args.notrunc)

    end_time = time.time()

    if args.showlog:
        rows, columns = os.popen('stty size', 'r').read().split()
        os.system('clear')
        print("=" * int(columns), "\n")

    cprint(print_title, 'green')
    cprint(f'{pretty_table(field_name, field_data, args.filter, showlog=args.showlog)}', 'green')

    if args.duration_time or args.showlog:
        Logging().log_print(f'Duration of Time : {end_time - start_time}', 'yellow', is_print=True)


if __name__ == '__main__':
    main()
