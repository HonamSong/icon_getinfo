#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import time
import inspect
import urllib3
import requests
import threading
import multiprocessing
from queue import Queue
from datetime import datetime
from termcolor import cprint
from prettytable import PrettyTable
from urllib.parse import urlparse

def todaydate(date_type=None):
    if date_type is None:
        return '%s' % datetime.now().strftime("%Y%m%d")
    elif date_type == "md":
        return '%s' % datetime.now().strftime("%m%d")
    elif date_type == "file":
        return '%s' % datetime.now().strftime("%Y%m%d_%H%M")
    elif date_type == "hour":
        return '%s' % datetime.now().strftime("%H")
    elif date_type == "ms":
        return '%s' % datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    elif date_type == "log_ms":
        return '%s' % datetime.now().strftime("%Y%m%d%H%M%S")
    elif date_type == "ms_text":
        return '%s' % datetime.now().strftime("%Y%m%d-%H%M%S%f")[:-3]
    elif date_type == "ifdb_time":
        return '%s' % datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

def disable_ssl_warnings():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_public_ipaddr(output=False):
    try:
        r = requests.get("https://api.ipify.org", verify=False).text.strip()
        if output:
            Logging().log_print(f'++ Get public IP  : {r}', "green")
        return r
    except:
        return None

def base_path():
    frame = inspect.stack()[1]
    module = inspect.getmodule(frame[0])
    filename = module.__file__
    return os.path.dirname(filename)

def check_dir(dir_path, create_if_missing=False):
    if os.path.isdir(dir_path):
        return True
    else:
        if create_if_missing:
            os.makedirs(dir_path, exist_ok=True)
            return True
        else:
            cprint(f'Directory "{dir_path}" does not found', 'red')
            return False

def chech_file(filename, path=None):
    orig_path = os.getcwd()
    if path:
        if check_dir(path):
            # path Change
            os.chdir(path)

    if os.path.isfile(filename):
        if path:
            os.chdir(orig_path)
            return os.path.join(path, filename)
        else:
            return os.path.join(filename)
    else:
        cprint(f'Check file : file "{filename}" does Not Found is file', 'red')
        return False

def single_list_check(data):
    import numpy as np
    arr = np.array(data)
    if len(arr.shape) == 1:
        return True
    else:
        return False

def pretty_table(filed_name, data, align="l", showlog=False):
    # https://pypi.org/project/prettytable/
    prettytable = PrettyTable()

    if single_list_check(data):
        prettytable.field_names = filed_name
        prettytable.add_row(data)
    else:
        idx = 1
        if filed_name:
            if "idx" not in filed_name[0]:
                filed_name.insert(0, 'idx')
            prettytable.field_names = filed_name

        Logging().log_print(f'{len(filed_name)}', 'yellow', is_print=showlog)

        for item in data:
            # Logging().log_print(f'{item}', 'yellow')
            item.insert(0, idx)
            prettytable.add_row(item)
            idx += 1

    # 왼쪽 정렬: l, 오른쪽 정렬 : r , 중앙 정렬 : c
    prettytable.align = f'{align}'

    return prettytable

class Color:
    # TextColor : Text Color
    grey = 'grey'
    red = 'red'
    green = 'green'
    yellow = 'yellow'
    blue = 'blue'
    magenta = 'magenta'
    cyan = 'cyan'
    white = 'white'

class BgColor:
    """
    :param BackGroundColor(Text highlights) : Text Background color
    """
    grey = 'on_grey'
    red = 'on_red'
    green = 'on_green'
    yellow = 'on_yellow'
    blue = 'on_blue'
    magenta = 'on_magenta'
    cyan = 'on_cyan'
    white = 'on_white'

class Logging:
    def __init__(self, log_path=None,
                 log_file=None, log_color='green', log_level='INFO', log_mode='print'):
        self.log_path = log_path
        self.log_file = log_file
        self.log_color = log_color
        self.log_level = log_level
        self.log_mode = log_mode

        """
        :param log_path: logging path name
        :param log_file: logging file name
        :param log_color: print log color
        :param log_level: logging level
        :param log_mode: print or loging mode ( default : print)
        :return:
        """

        if self.log_path:
            check_dir(self.log_path, create_if_missing=True)
        else:
            self.log_path = os.path.join(base_path(), "logs")
            check_dir(self.log_path, create_if_missing=True)

        if not self.log_file:
            # self.log_file = f'log_{todaydate()}.log'
            frame = inspect.stack()[1]
            module = inspect.getmodule(frame[0])
            filename = module.__file__
            self.log_file = filename.split('/')[-1].replace('.py', f'_{todaydate()}.log')

        self.log_file = os.path.join(self.log_path, self.log_file)

    def log_write(self, log_msg):
        if log_msg:
            with open(self.log_file, 'a+') as f:
                f.write(f'{log_msg}\n')

    def log_print(self, msg, color=None, level=None, is_print=False):
        line_num = inspect.currentframe().f_back.f_lineno

        if not color:
            color = self.log_color

        if level == 'error' or level == 'err' or level == 'ERROR' or level == 'ERR':
            color = Color.red
            level = 'ERROR'
        elif level == 'warning' or level == 'warn' or level == 'WARNING' or level == 'WARN':
            color = Color.magenta
            level = 'WARN'
        elif level == 'debug' or level == 'Debug':
            color = Color.yellow
            level = 'DEBUG'
        else:
            level = self.log_level

        print_msg = f'[{todaydate(date_type="ms")}] [{level.upper():5}] | line.{line_num} | {msg}'

        if self.log_mode == 'print' or not self.log_mode:
            if is_print:
                cprint(print_msg, color)
        elif self.log_mode == 'write':
            self.log_write(print_msg,)
        elif self.log_mode == 'all':
            if is_print:
                cprint(print_msg, color)
            self.log_write(print_msg,)

class IconNodeGetInfo:
    def __init__(self, url='http://localhost', port='9000', showlog=False):
        self.url = url
        self.port = port
        self.chaininfo = None
        self.chain_inspect = None
        self.pool = multiprocessing.Pool(processes=3)

        self.logging = Logging(log_mode='print')
        self.showlog = showlog

        self.chain_url_path = "admin/chain/icon_dex"
        self.system_url_path = "admin/system"
        self.data_q = Queue()
        self.m_field_name = None

        if "http://" not in self.url:
            self.url = f'http://{self.url}'

        # URL에 port 포함 여부 확인
        self.url_match = "(http|https)\\:\\/\\/([a-z]|[0-9]).*:([0-9]){1,5}"
        if re.match(self.url_match, self.url):
            url_args = urlparse(self.url)
            self.url = f'{url_args.scheme}://{url_args.hostname}'
            self.port = url_args.port

        self.logging.log_print(f'++ URL : {self.url}', 'green', is_print=self.showlog)

    def get_requests(self, url, conn_timeout=5):
        if "http://" not in url:
            url = f'http://{url}'

        try:
            # self.logging.log_print(f'requests URL : {url}', 'green')
            with requests.session() as s:
                res = s.get(url, verify=False, timeout=conn_timeout)
                res_state = res.status_code
                res_json = res.json()
            s.close()
        except urllib3.exceptions.ConnectTimeoutError as e:
            self.logging.log_print(f'{e}, {url}', 'red', 'error', is_print=self.showlog)
        except requests.exceptions.ConnectionError:
            self.logging.log_print(f'-- Connection Fail!! => {url}', 'red', 'error', is_print=self.showlog)
            res_state = 599
            res_json = None

        return res_state, res_json

    def get_node(self, url=None, port=None, get_local=False,
                 get_chain=False, get_inspect=False, get_system=False, get_all=False, no_trunc=False):
        field_name = []

        if not url:
            url = self.url
        if not port:
            port = self.port

        self.logging.log_print(f'Check Node Address : {url}', 'green', is_print=self.showlog)

        node_info = {
            "ip_addr": urlparse(url).hostname,
        }

        res_state, res_json = self.get_requests(f'{url}:{port}/{self.chain_url_path}')
        if get_local:
            if res_state != 200:
                self.logging.log_print(f'Connection Fail!! : {url}', 'red', 'error')
                sys.exit(1)

        sys_res_state, sys_res_json = self.get_requests(f'{url}:{port}/{self.system_url_path}')
        if res_state == 200:
            sys_res_json['sys_config'] = sys_res_json.pop('config')

        if res_json and sys_res_json:
            node_res_json = dict(res_json, **sys_res_json)
        else:
            node_res_json = None

        chain_res_config = node_res_json.get('config') if res_json else f'599 error'
        sys_res_setting = node_res_json.get('setting') if sys_res_json else f'599 error'
        sys_res_config = node_res_json.get('sys_config') if sys_res_json else f'599 error'

        if get_chain or get_inspect or get_all:
            if node_res_json:
                if len(node_res_json.get('lastError')) == 0:
                    lasterror_value = '-'
                else:
                    lasterror_value = node_res_json.get('lastError')
            else:
                lasterror_value = f'-'

            node_chain = {
                'cid': node_res_json.get('cid') if node_res_json else f'599 error',
                'nid': node_res_json.get('nid') if node_res_json else f'-',
                'state': node_res_json.get('state') if node_res_json else f'-',
                'height': node_res_json.get('height') if node_res_json else f'-'
            }

            if no_trunc:
                node_chain['lastError'] = lasterror_value

            node_info = dict(node_info, **node_chain)

        if get_inspect or get_all:
            if node_res_json:
                if len(chain_res_config.get("seedAddress")) >= 30:
                    seedaddress_rst = f'{chain_res_config.get("seedAddress")[0:30]}...'
                else:
                    seedaddress_rst = f'{chain_res_config.get("seedAddress")}'
            else:
                seedaddress_rst = f'-'

            node_inspect = {
                "channel": node_res_json.get('channel') if node_res_json else f'-',
                "role": chain_res_config.get('role') if node_res_json else f'-',
                "dbType": chain_res_config.get('dbType') if node_res_json else f'-',
                "address": sys_res_setting.get('address')[0:8] if node_res_json else f'-',
                "seedAddress": seedaddress_rst if node_res_json else f'-',
            }

            if no_trunc:
                node_inspect['address'] = sys_res_setting.get('address') if node_res_json else f'-'
                node_inspect['seedAddress'] = chain_res_config.get("seedAddress") if node_res_json else f'-'
                node_inspect['autoStart'] = chain_res_config.get('autoStart') if node_res_json else f'-'

            node_info = dict(node_info, **node_inspect)

        if get_system or get_all:
            if node_res_json:
                if len(sys_res_config.get('rpcDefaultChannel')) == 0:
                    rpcdefaultchannel_value = '-'
                else:
                    rpcdefaultchannel_value = sys_res_config.get('rpcDefaultChannel')
            else:
                rpcdefaultchannel_value = f'-'

            node_system = {
                "buildVersion": node_res_json.get('buildVersion') if node_res_json else f'599 error',
                "p2p": sys_res_setting.get('p2p') if node_res_json else f'-',
                "rpcDump": sys_res_setting.get('rpcDump') if node_res_json else f'-',
                "rpcIncludeDebug": sys_res_config.get('rpcIncludeDebug') if node_res_json else f'-',
                "rpcBatchLimit": sys_res_config.get('rpcBatchLimit') if node_res_json else f'-',
            }

            if no_trunc:
                node_system['rpcDefaultChannel'] = rpcdefaultchannel_value
                node_system['eeInstances'] = sys_res_config.get('eeInstances') if node_res_json else f'-'
                node_system['buildTags'] = node_res_json.get('buildTags') if node_res_json else f'-'

            node_info = dict(node_info, **node_system)

        for key in node_info.keys():
            field_name.append(key)

        if get_local:
            node_value = []
            for value in node_info.values():
                node_value.append(value)
            node_info = node_value

        self.logging.log_print(f'++ field name : {field_name}', 'green', is_print=self.showlog)
        self.logging.log_print(f'++ field data : {node_info}', 'green', is_print=self.showlog)

        return node_res_json, field_name, node_info

    def get_all_node_ip(self,):
        res_json_data, field_name, node_info = self.get_node(get_inspect=True)
        if node_info.get('role') == 0:
            seeds_ips = list(res_json_data.get('module').get('network').get('p2p').get('seeds').keys())
            for seed_ip in seeds_ips:
                node_url = f'http://{seed_ip.replace(":7100", "")}'
                res_json, field_name, node_info = self.get_node(url=node_url, get_inspect=True)
                if node_info.get('role') == 1 or node_info.get('role') == 3:
                    res_json_data = res_json
                    break
        roots_ips = list(res_json_data.get('module').get('network').get('p2p').get('roots').keys())
        seeds_ips = list(res_json_data.get('module').get('network').get('p2p').get('seeds').keys())
        nodes_ip = set(roots_ips + seeds_ips + [f'{urlparse(self.url).hostname}:7100'])

        self.logging.log_print(f'++ get_all_node_ip : {nodes_ip}', 'magenta', is_print=self.showlog)

        return nodes_ip

    def get_node_multi(self, node_ip, field_name, get_type, no_trunc=False):
        get_info = []
        node_info = None
        node_url = f'http://{node_ip.replace(":7100", "")}'

        self.logging.log_print(f'++ get_node_multi| Check URL = {node_url} , get_type = {get_type}',
                               color='magenta', is_print=self.showlog)

        if get_type == 'chain':
            res_json, field_name, node_info = self.get_node(url=node_url, get_chain=True, no_trunc=no_trunc)

        if get_type == 'chain_inspect':
            res_json, field_name, node_info = self.get_node(url=node_url, get_chain=True,
                                                            get_inspect=True, no_trunc=no_trunc)

        if get_type == 'system':
            res_json, field_name, node_info = self.get_node(url=node_url, get_system=True, no_trunc=no_trunc)

        if get_type == 'all' or not get_type:
            res_json, field_name, node_info = self.get_node(url=node_url, get_all=True, no_trunc=no_trunc)

        for field in field_name:
            if field == "ip_addr" and urlparse(self.url).hostname == node_ip.replace(":7100", ""):
                get_info.append(f'{node_ip.replace(":7100", "")}(local)')
            else:
                get_info.append(node_info.get(field))

        self.data_q.put(get_info)
        self.m_field_name = field_name

        self.logging.log_print(f'++ now queue size : {self.data_q.qsize()}', 'yellow', 'debug', is_print=self.showlog)

    def get_all_node(self, get_type='all', no_trunc=False):

        node_result = []
        thread_list = []

        field_name = ["ip_addr", "cid", "nid", "channel", "state", "role", "address", "height"]

        all_node_ip = self.get_all_node_ip()
        self.logging.log_print(f'++ get_all_node_ip : {all_node_ip}', 'green', is_print=self.showlog)

        for node_ip in all_node_ip:
            t = threading.Thread(target=self.get_node_multi, args=(node_ip, field_name, get_type, no_trunc))
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        while True:
            if self.data_q.qsize() == 0:
                self.data_q.queue.clear()
                break
            else:
                node_result.append(self.data_q.get())

        field_name = self.m_field_name
        self.logging.log_print(f'++ get_all_node | field name = {field_name}', 'green', is_print=self.showlog)
        self.logging.log_print(f'++ get_all_node | field data \n {json.dumps(node_result)}',
                               color='green', is_print=self.showlog)

        return field_name, node_result


def parse_args(**kwargs):
    import argparse
    parser = argparse.ArgumentParser(description="Get icon node information")

    parser.add_argument("-m", "--mode", default='chain', help=f'Get mode type',
                        choices=['chain', 'chain_detail', 'chain_inspect', 'system', 'all', 'all_chain',
                                 'all_chain_inspect', 'all_chain_detail', 'all_system', 'all_node'])
    parser.add_argument("-u", "--url", default="http://localhost")
    parser.add_argument("--duration_time", action='store_true', help='Show Duration of time')
    parser.add_argument("--notrunc", action='store_true', help="Don't truncate output")
    parser.add_argument("--showlog", action='store_true', help='show running log')

    return parser.parse_args()

def print_banner():
    banner = '''starting to IconNetwork Node Information !!
     _   _           _        ___        __
    | \ | | ___   __| | ___  |_ _|_ __  / _| ___
    |  \| |/ _ \ / _` |/ _ \  | || '_ \| |_ / _ \\
    | |\  | (_) | (_| |  __/  | || | | |  _| (_) |
    |_| \_|\___/ \__,_|\___| |___|_| |_|_|  \___/

    '''

    for line in banner.split('\n'):
        cprint(f'{line}', 'green')

    # delete variables !!
    del banner


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
    args = parse_args()

    print_title = None
    field_name = None
    field_data = None

    get_node = IconNodeGetInfo(url=args.url, showlog=args.showlog)
    print_banner()

    if len(sys.argv) == 1:
        print(json.dumps(get_node.get_node(get_local=True, get_chain=True), indent=4))
    else:
        cprint(f'    + input Check node ip : {args.url}\n', 'green')
        print_title, field_name, field_data = main_run(get_node, args.mode, args.notrunc)

    end_time = time.time()

    if args.showlog:
        rows, columns = os.popen('stty size', 'r').read().split()
        os.system('clear')
        print("=" * int(columns), "\n")

    cprint(print_title, 'green')
    cprint(f'{pretty_table(field_name, field_data)}', 'green')

    if args.duration_time or args.showlog:
        Logging().log_print(f'Duration of Time : {end_time - start_time}', 'yellow', is_print=True)


if __name__ == '__main__':
    main()
