#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import inspect
import requests
from datetime import datetime
from termcolor import cprint
from prettytable import PrettyTable

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

def pretty_table(filed_name, data, filter_head, align="l", showlog=False):
    # https://pypi.org/project/prettytable/
    prettytable = PrettyTable(padding_width=1, header_style="title")
    is_not_field = False

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
    if 'idx' in prettytable.field_names:
        default_field = ['idx', 'ip_addr']
        prettytable.align['idx'] = 'r'
    else:
        default_field = ['ip_addr']

    if filter_head:
        for ff_name in filter_head:
            if ff_name in prettytable.field_names:
                if ff_name not in default_field:
                    default_field.append(ff_name)
            else:
                Logging().log_print(f'Not found field and Exclude field : {ff_name}', 'red', 'error', is_print=showlog)
                default_field = prettytable.field_names
                is_not_field = True

        filter_head = default_field
        Logging().log_print(f'prettytable.get_string : {filter_head}', 'magenta', is_print=showlog)
        if is_not_field:
            Logging().log_print(f'filter field name Check ', 'red', is_print=True)

        return prettytable.get_string(fields=filter_head)
    else:
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

        if self.log_mode != 'print':
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

