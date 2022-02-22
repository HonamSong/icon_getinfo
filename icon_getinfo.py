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

def pretty_table(filed_name, data, align="l"):
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

        # Logging().log_print(f'{len(filed_name)}', 'yellow')

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

    def log_print(self, msg, color=None, level=None):
        line_num = inspect.currentframe().f_back.f_lineno

        if not color:
            color = self.log_color

        if level == 'error' or level == 'err' or level == 'ERROR' or level == 'ERR':
            color = Color.red
            level = 'ERROR'
        elif level == 'warning' or level == 'warn' or level == 'WARNING' or level == 'WARN':
            color = Color.magenta
            level = 'WARN'
        else:
            level = self.log_level

        print_msg = f'[{todaydate(date_type="ms")}] [{level.upper():5}] | line.{line_num} | {msg}'

        if self.log_mode == 'print' or not self.log_mode:
            cprint(print_msg, color)
        elif self.log_mode == 'write':
            self.log_write(print_msg,)
        elif self.log_mode == 'all':
            cprint(print_msg, color)
            self.log_write(print_msg,)

class IconNodeGetInfo:
    def __init__(self, url='http://localhost', port='9000'):
        self.url = url
        self.port = port
        self.chaininfo = None
        self.chain_inspect = None
        self.pool = multiprocessing.Pool(processes=3)

        self.logging = Logging(log_mode='all')

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

        self.pub_ip_addr = get_public_ipaddr()
        # logging.log_print(f' init : {self.url}', 'red')

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
            self.logging.log_print(f'{e}, {url}', 'red', 'error')
        except requests.exceptions.ConnectionError:
            # self.logging.log_print(f'Error : {e}, {url}', 'red')
            self.logging.log_print(f'Connection Fail!! => {url}', 'red', 'error')
            res_state = 503
            res_json = None

        return res_state, res_json

    def get_chain(self, url=None, port=None, get_local=False, get_inspect=False):
        field_name = []

        if not url:
            url = self.url
        if not port:
            port = self.port

        res_state, res_json = self.get_requests(f'{url}:{port}/{self.chain_url_path}')
        sys_res_state, sys_res_json = self.get_requests(f'{url}:{port}/{self.system_url_path}')

        chain_info = {
            "ip_addr": urlparse(url).hostname,
            'cid': res_json.get('cid') if res_json else f'503 error',
            'nid': res_json.get('nid') if res_json else f'503 error',
            'state': res_json.get('state') if res_json else f'503 error',
            'height': res_json.get('height') if res_json else f'503 error',
            'lastError': res_json.get('lastError') if res_json else f'503 error'
        }

        if get_inspect:
            chain_config = res_json.get('config') if res_json else f'503 error'
            if res_json:
                if len(chain_config.get("seedAddress")) >= 60:
                    seedaddress_rst = f'{chain_config.get("seedAddress")[0:60]}...'
                else:
                    seedaddress_rst = f'{chain_config.get("seedAddress")}'
            else:
                seedaddress_rst = f'503 error'

            chain_inspect = {
                "channel": res_json.get('channel') if res_json else f'503 error',
                "role": chain_config.get('role') if res_json else f'503 error',
                "dbType": chain_config.get('dbType') if res_json else f'503 error',
                # "address": sys_res_json.get('setting').get('address') if res_json else f'503 error',
                "address": sys_res_json.get('setting').get('address')[0:8] if res_json else f'503 error',
                "autoStart": chain_config.get('autoStart') if res_json else f'503 error',
                "seedAddress": seedaddress_rst if res_json else f'503 error',
            }
            chain_info = dict(chain_info, **chain_inspect)

        for key in chain_info.keys():
            field_name.append(key)

        if get_local:
            chain_value = []
            for value in chain_info.values():
                chain_value.append(value)
            chain_info = chain_value

        # self.logging.log_print(json.dumps(chain_info), "green")

        return res_json, field_name, chain_info

    def get_all_node_ip(self,):
        res_json_data, field_name, chain_info = self.get_chain(get_inspect=True)
        if chain_info.get('role') == 0:
            seeds_ips = list(res_json_data.get('module').get('network').get('p2p').get('seeds').keys())
            for seed_ip in seeds_ips:
                node_url = f'http://{seed_ip.replace(":7100", "")}'
                res_json, field_name, chain_info = self.get_chain(url=node_url, get_inspect=True)
                # self.logging.log_print(f'get_all_node_ip|{seed_ip}/role:{chain_info.get("role")}', color='yellow')
                if chain_info.get('role') == 1 or chain_info.get('role') == 3:
                    res_json_data = res_json
                    break
        roots_ips = list(res_json_data.get('module').get('network').get('p2p').get('roots').keys())
        seeds_ips = list(res_json_data.get('module').get('network').get('p2p').get('seeds').keys())
        nodes_ip = set(roots_ips + seeds_ips + [urlparse(self.url).hostname])
        # roots_ips = list(res_json_data.get('module').get('network').get('p2p').get('roots').keys())
        # seeds_ips = list(res_json_data.get('module').get('network').get('p2p').get('seeds').keys())
        # nodes_ip = []
        # for nip in roots_ips, seeds_ips, urlparse(self.url).hostname:
        #    cprint(f'{nip}', "red")
        #    if nip not in nodes_ip:
        #        nodes_ip.append(nip)

        # self.logging.log_print(f'get_all_node_ip | root | {roots_ips}', 'yellow')
        # self.logging.log_print(f'get_all_node_ip | seed | {seeds_ips}', 'yellow')
        # self.logging.log_print(f'get_all_node_ip | total| {nodes_ip}', 'yellow')

        return nodes_ip

    def get_chain_multi(self, node_ip, field_name):

        get_info = []
        node_url = f'http://{node_ip.replace(":7100", "")}'
        res_json, field_name, chain_info = self.get_chain(url=node_url, get_inspect=True)
        for field in field_name:
            if field == "ip_addr" and urlparse(self.url).hostname == node_ip.replace(":7100", ""):
                get_info.append(f'{node_ip.replace(":7100", "")}(local)')
            else:
                get_info.append(chain_info.get(field))
        self.data_q.put(get_info)
        self.m_field_name = field_name

        # chain_result.append(get_info)

    def get_chain_all(self,):

        chain_result = []
        field_name = ["ip_addr", "cid", "nid", "channel", "state", "role", "address", "height"]

        all_node_ip = self.get_all_node_ip()
        # self.logging.log_print(f'get_chain_all | {all_node_ip}')

        thread_list = []

        for node_ip in all_node_ip:
            t = threading.Thread(target=self.get_chain_multi, args=(node_ip, field_name))
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        # self.logging.log_print(f'queue size : {self.data_q.qsize()}', 'yellow')
        while True:
            if self.data_q.qsize() == 0:
                break
            else:
                chain_result.append(self.data_q.get())

        # self.logging.log_print(f'{json.dumps(chain_result, indent=4)}', 'yellow')
        # self.logging.log_print(f'{chain_result}', 'magenta')
        # self.logging.log_print(f'{type(chain_result)}', 'magenta')

        field_name = self.m_field_name

        return field_name, chain_result

    def get_chain_all_none_multi(self,):
        chain_result = []
        field_name = ["ip_addr", "cid", "nid", "channel", "state", "role", "address", "height"]

        all_node_ip = self.get_all_node_ip()
        # self.logging.log_print(f'get_chain_all | {all_node_ip}')

        for node_ip in all_node_ip:
            # self.logging.log_print(f'get_chain_all | check ip = {node_ip}')
            node_url = f'http://{node_ip.replace(":7100", "")}'
            res_json, field_name, chain_info = self.get_chain(url=node_url, get_inspect=True)
            get_info = []
            for field in field_name:
                if field == "ip_addr" and urlparse(self.url).hostname == node_ip:
                    get_info.append(f'{node_ip.replace(":7100", "")}(local)')
                else:
                    get_info.append(chain_info.get(field))
            chain_result.append(get_info)
            del get_info

        # self.logging.log_print(f'{chain_result}', 'magenta')
        # self.logging.log_print(f'{type(chain_result)}', 'magenta')

        return field_name, chain_result

    def get_system(self, url=None, port=None, get_local=False):
        get_field_name = []
        system_value = []

        if not url:
            url = self.url
        if not port:
            port = self.port

        sys_res_state, sys_res_json = self.get_requests(f'{url}:{port}/{self.system_url_path}')
        res_setting = sys_res_json.get('setting') if sys_res_json else f'503 error'
        res_config = sys_res_json.get('config') if sys_res_json else f'503 error'

        system_info = {
            "ip_addr": urlparse(url).hostname,
            "buildVersion": sys_res_json.get('buildVersion') if sys_res_json else f'503 error',
            "buildTags": sys_res_json.get('buildTags') if sys_res_json else f'503 error',
            "address": res_setting.get('address') if sys_res_json else f'503 error',
            "p2p": res_setting.get('p2p') if sys_res_json else f'503 error',
            "rpcDump": res_setting.get('rpcDump') if sys_res_json else f'503 error',
            "eeInstances": res_config.get('eeInstances') if sys_res_json else f'503 error',
            "rpcDefaultChannel": res_config.get('rpcDefaultChannel') if sys_res_json else f'503 error',
            "rpcIncludeDebug": res_config.get('rpcIncludeDebug') if sys_res_json else f'503 error',
            "rpcBatchLimit": res_config.get('rpcBatchLimit') if sys_res_json else f'503 error',
        }
        for key in system_info.keys():
            get_field_name.append(key)

        if get_local:
            for value in system_info.values():
                system_value.append(value)
            system_info = system_value

        # self.logging.log_print(json.dumps(system_info), "green")
        return sys_res_json, get_field_name, system_info

    def get_system_multi(self, node_ip, field_name):

        get_info = []
        node_url = f'http://{node_ip.replace(":7100", "")}'
        res_json, field_name, system_info = self.get_system(url=node_url)
        for field in field_name:
            if field == "ip_addr" and urlparse(self.url).hostname == node_ip.replace(":7100", ""):
                get_info.append(f'{node_ip.replace(":7100", "")}(local)')
            else:
                get_info.append(system_info.get(field))
        self.data_q.put(get_info)
        self.m_field_name = field_name

        # chain_result.append(get_info)

    def get_system_all(self,):

        system_result = []
        thread_list = []
        field_name = ["ip_addr", "buildVersion", "buildTags", "address", "p2p",
                      "rpcDump", "eeInstances", "rpcIncludeDebug", "rpcDefaultChannel"]

        all_node_ip = self.get_all_node_ip()

        for node_ip in all_node_ip:
            t = threading.Thread(target=self.get_system_multi, args=(node_ip, field_name))
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        # self.logging.log_print(f'queue size : {self.data_q.qsize()}', 'yellow')
        while True:
            if self.data_q.qsize() == 0:
                break
            else:
                system_result.append(self.data_q.get())

        field_name = self.m_field_name

        return field_name, system_result

    def get_system_all_none_multi(self,):
        system_result = []
        field_name = ["ip_addr", "buildVersion", "buildTags", "address", "p2p",
                      "rpcDump", "eeInstances", "rpcIncludeDebug", "rpcDefaultChannel"]

        all_node_ip = self.get_all_node_ip()

        for node_ip in all_node_ip:
            self.logging.log_print(f'get_system_all | check ip = {node_ip}')
            node_url = f'http://{node_ip.replace(":7100", "")}'
            res_json, field_name, system_info = self.get_system(url=node_url)
            get_info = []
            for field in field_name:
                if field == "ip_addr" and get_public_ipaddr() == node_ip:
                    get_info.append(f'{node_ip.replace(":7100", "")}(local)')
                else:
                    get_info.append(system_info.get(field))
            system_result.append(get_info)
            del get_info

        return field_name, system_result


def parse_args(**kwargs):
    import argparse
    parser = argparse.ArgumentParser(description="Get icon node information")

    parser.add_argument("-m", "--mode", default='chain',
                        help=f' [ chain | chain_all | chain_detail(or chain_inspect) | system | system_all | all] ')
    parser.add_argument("-u", "--url", default="http://localhost")

    return parser.parse_args()


def main():
    start_time = time.time()
    disable_ssl_warnings()
    args = parse_args()

    get_node = IconNodeGetInfo(url=args.url)

    if len(sys.argv) == 1:
        print(json.dumps(get_node.get_chain(), indent=4))
    else:
        print(f'url : {args.url}')
        if args.mode == 'chain':
            res_json, field_name, field_data = get_node.get_chain(get_local=True)
            cprint(f'{pretty_table(field_name, field_data)}', 'green')

        if args.mode == 'chain_all' or args.mode == 'all':
            field_name, field_data = get_node.get_chain_all()
            cprint(f'< Icon Network All node information >', 'green')
            cprint(f'{pretty_table(field_name, field_data)}', 'green')

        if args.mode == 'chain_detail' or args.mode == "chain_inspect":
            res_json, field_name, field_data = get_node.get_chain(get_local=True, get_inspect=True)
            cprint(f'< Localhost Icon Node information >', 'green')
            cprint(f'{pretty_table(field_name, field_data)}', 'green')

        if args.mode == 'system':
            res_json, field_name, field_data = get_node.get_system(get_local=True)
            cprint(f'< Icon Network node System information >', 'green')
            cprint(f'{pretty_table(field_name, field_data)}', 'green')

        if args.mode == 'system_all' or args.mode == 'all':
            field_name, field_data = get_node.get_system_all()
            cprint(f'< Icon Network node All System information >', 'green')
            cprint(f'{pretty_table(field_name, field_data)}', 'green')
    end_time = time.time()
    Logging().log_print(f'Total time  : {end_time - start_time}', 'yellow')


if __name__ == '__main__':
    main()
