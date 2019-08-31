# -*- coding: utf-8 -*-
import os
import subprocess

from datetime import datetime
from sys import platform
from subprocess import Popen, PIPE

OKGREEN = '\033[92m'
WARNING = '\033[93m'
ENDC = '\033[0m'


def print_message(code, message):
    code_str = OKGREEN if code == 'ok' else WARNING
    type_code = '[Info]' if code == 'ok' else '[Warning]'
    base_message = datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ' - ' + code_str + type_code + ENDC
    print(base_message + ' ' + message)


def read_file(path):
    content = ""
    if os.path.exists(path):
        file = open(path, 'r')
        content = file.read()
    else:
        print_message('warning', 'Fichero {0} no encontrado'.format(path))
    return content


def execute_command(command):
    response_splitted = ''
    response_command = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    response_command = response_command.stdout.read()
    if isinstance(response_command, bytes):
        response_splitted = response_command.decode('utf-8')
    return response_splitted


def check_if_linux_system():
    return True if platform in ["linux", "linux2"] else False


def check_if_is_root():
    return True if os.getuid() == 0 else False


def check_if_package_installed(package):
    call_result = execute_command("which " + package)
    return True if call_result else False


def check_if_process_is_active(process):
    command = Popen(["service", str(process), "status"],
                    stdout=PIPE, stderr=PIPE)
    out, err = command.communicate()
    if out:
        return True
    else:
        return False


def get_list_services_starts_on_boot():
    command = 'systemctl list-units --type service'
    response_command = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True).stdout.read()
    response_splitted = response_command.decode('utf-8').split('\n')
    list_process_to_show = []
    for line in response_splitted:
        info = line.split()
        if info and info[0].endswith('.service'):
            list_process_to_show.append(
                (info[0], ' '.join(info[4:]))
            )
    return list_process_to_show


def get_list_open_ports():
    command = 'netstat -lntu'
    response_command = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True).stdout.read()
    response_splitted = response_command.decode('utf-8').split('\n')
    list_connections = []
    for line in response_splitted:
        info = line.split()
        if info and (info[0].startswith('tcp') or info[0].startswith('udp')):
            ip = info[3][:info[3].rfind(':')]
            port = info[3][info[3].rfind(':') + 1:]
            list_connections.append(
                (info[0], ip, port)
            )
    return list_connections


def get_config_from_file(path_file_to_check, ignore_lines_start_with, return_full_content=False):
    config = dict()
    content = read_file(path_file_to_check).splitlines()
    config_lines = [text for text in content if text and not text.startswith(ignore_lines_start_with)]
    if return_full_content:
        return config_lines
    for line in config_lines:
        line = line.replace("\t", " ")
        params = line.split(" ")
        if params:
            config[params[0]] = ''.join(params[1:])
    return config


def get_pam_config(path_file_to_check, ignore_lines_start_with):
    pam_file = {}
    content = read_file(path_file_to_check).splitlines()
    config_lines = [text.strip() for text in content if text and not text.strip().startswith(ignore_lines_start_with)]
    for line in config_lines:
        line = line.replace("\t", " ")
        params = line.split()
        if params:
            if params[0] in pam_file:
                actual_config = pam_file.get(params[0])
                actual_config.append(''.join(params[1:]))
                pam_file[params[0]] = actual_config
            else:
                pam_file[params[0]] = [''.join(params[1:])]
    return pam_file


def check_extra_config(json_file_config):
    import json

    if not os.path.exists(json_file_config):
        print_message('warning', 'Fichero json no encontrado {0}'.format(json_file_config))
        return []
    config_data = {}
    with open(json_file_config, 'r') as file:
        config_data = json.load(file)
    list_results = []

    for key in config_data:
        configs_to_check = config_data[key]
        for config in configs_to_check:
            if len(config) != 6:
                continue
            path_to_check = config[0]
            property = config[1]
            lines_to_ignore = config[2]
            separator = config[3]
            name_in_report = config[4]
            expected_value = config[5]

            config_file = get_config_from_file(path_to_check, lines_to_ignore, True)
            dict_config = {}
            for line in config_file:
                if separator:
                    line_splitted = line.split(separator)
                else:
                    line_splitted = line.split()
                if line_splitted[0] in dict_config:
                    actual_values_for_key = dict_config[line_splitted[0]]
                    actual_values_for_key.append(''.join(line_splitted[1:]))
                    dict_config[line_splitted[0]] = actual_values_for_key
                else:
                    dict_config[line_splitted[0]] = [''.join(line_splitted[1:])]
            result = 'Incorrecto'
            if property in dict_config:
                for field in dict_config[property]:
                    if expected_value in field:
                        result = 'Correcto'
                    else:
                        result = 'Incorrecto'
                        break
        list_results.append(
            ('[' + key + ']' + name_in_report, result)
        )
    return list_results


def generate_pdf(html):
    try:
        from weasyprint import HTML, CSS
        print_message('ok', 'Generando PDF')
        html = html.replace('collapse', '')
        css = "@page {size: Letter; margin: 0in 0.44in 0.2in 0.44in; font-size:10px !important}"
        css1 = """
        th {
                        font-weight: inherit;
                    }
                    .panel-heading {
                        background-color: #7BA7C7 !important;
                    }
                    table {
                        border-collapse: separate;
                        white-space: normal;
                        line-height: normal;
                        font-size: medium;
                        border-spacing: 2px;
                    }
                    .title_a {
                        padding-left: 2px;
                        font-weight: bold;
                        color: white !important;
                        font-family: TAHOMA;
                        font-size: 14px;
                    }
                    .panel-body {
                        padding-left: 16px;
                        padding-right: 00px;
                        font-size: 11pt;
                        margin-bottom: -1px;
                        color: #000000;
                        padding-top: 4px;
                        font-family: Tahoma;
                        position: relative;
                        word-wrap: break-word;
                        box-sizing: border-box;
                    }
                    thead > tr{
                        height: 35px;
                        color: #4169E1;
                        text-align: left;
                        font-weight: bold;
                    }
                    tbody > tr > th{
                        font-size: 14px;
                        font-weight: 400;
                        height: 18px;
                        line-height: normal;
                        vertical-align: top;
                    }
                    .div_title_top{
                        BORDER-RIGHT: #bbbbbb 1px solid;
                        PADDING-RIGHT: 5em;
                        BORDER-TOP: #bbbbbb 1px solid;
                        DISPLAY: block;
                        PADDING-LEFT: 8px;
                        FONT-WEIGHT: bold;
                        FONT-SIZE: 12pt;
                        MARGIN-BOTTOM: -1px;
                        MARGIN-LEFT: 0px;
                        BORDER-LEFT: #bbbbbb 1px solid;
                        margin-right: 0px;
                        CURSOR: hand;
                        COLOR: #FFFFFF;
                        MARGIN-RIGHT: 0px;
                        PADDING-TOP: 4px;
                        BORDER-BOTTOM: #bbbbbb 1px solid;
                        FONT-FAMILY: Tahoma;
                        POSITION: relative;
                        HEIGHT: 2.25em;
                        background-color: #4169E1 !important;
                        border-radius: 4px;
                    }
        """
        HTML(string=html).write_pdf('resultado_ens.pdf', stylesheets=[CSS('statics/css/bootstrap.min.css'), CSS(string=css), CSS(string=css1)])
        print_message('ok', 'Fichero PDF generado')
    except ImportError:
        print_message('error', 'WeasyPrint no instalado, no se puede generar el documento PDF')
