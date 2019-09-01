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
    """Show message in terminal with a color which it depends of code value.

    Args:
        code (str): Code for color message.
        message (str): Message to show in terminal.
    """
    code_str = OKGREEN if code == 'ok' else WARNING
    type_code = '[Info]' if code == 'ok' else '[Warning]'
    base_message = datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ' - ' + code_str + type_code + ENDC
    print(base_message + ' ' + message)


def read_file(path):
    """Check if path exists and returns content.

    Args:
        path (str): Path file.

    Returns:
        str: File content if exists if not empy string.
    """
    content = ""
    if os.path.exists(path):
        file = open(path, 'r')
        content = file.read()
    else:
        print_message('warning', 'Fichero {0} no encontrado'.format(path))
    return content


def execute_command(command):
    """Execute command using subprocess and with param shell to True.

    Args:
        command (str): Command to execute with subprocess.

    Returns:
        str: Command response in utf-8 format.
    """
    response_splitted = ''
    response_command = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    response_command = response_command.stdout.read()
    if isinstance(response_command, bytes):
        response_splitted = response_command.decode('utf-8')
    return response_splitted


def check_if_linux_system():
    """Check if system is linux.

    Returns:
        boolean: True if system is linux system if not False.
    """
    return True if platform in ["linux", "linux2"] else False


def check_if_is_root():
    """Check if app is executed with sudo perms.

    Returns:
        boolean: True if uid is 0 if not False.
    """
    return True if os.getuid() == 0 else False


def check_if_package_installed(package):
    """Check if a package is installed in the system.

    Args:
        package (str): package name.

    Returns:
        boolean: True if package in system if not False.

    """
    call_result = execute_command("which " + package)
    return True if call_result else False


def check_if_process_is_active(process):
    """Check if a process is active

    Args:
        process (str): process name.

    Returns:
        boolean: True if service is running if not False.
    """
    command = Popen(["service", str(process), "status"],
                    stdout=PIPE, stderr=PIPE)
    out, err = command.communicate()
    if out:
        return True
    else:
        return False


def get_list_services_start_on_boot():
    """Return list of tuples with info about services start on boot

    Returns:
        list: list of tuples. Each tuple contains service name and it description.
    """
    response_command = execute_command('systemctl list-units --type service')
    response_splitted = response_command.splitlines()
    list_process_to_show = []
    for line in response_splitted:
        info = line.split()
        if info and info[0].endswith('.service'):
            list_process_to_show.append(
                (info[0], ' '.join(info[4:]))
            )
    return list_process_to_show


def get_list_open_ports():
    """Return list of tuples with info about open ports

    Returns:
        list: list of tuples. Each tuple contains info about protocol, ip and port.
    """
    response_command = execute_command('netstat -lntu')
    response_splitted = response_command.split('\n')
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
    """Return dict with content file parsed. It Works for files with key value

        Args:
            path_file_to_check (str): path file.
            ignore_lines_start_with (str): string to avoid add lines start with this value.
            return full_content (boolean): boolen to return full content without lines start with ignore_lines_start_with value.

        Returns:
            str: content file without lines start with ignore_lines_start_with value.
            dict: content parsed with key value from file.
    """
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
    """Return dict with content file parsed. It Works for files with key value. Value is a list.

    Args:
        path_file_to_check (str): path file.
        ignore_lines_start_with (str): string to avoid add lines start with this value.

    Returns:
        dict: content parsed with key value (list) from file.
    """
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
    """Read content from json file and generate list which contains result of parsing the file

    Args:
        json_file_config (str): path file.

    Returns:
        list: list of tuples. Each tuple contains info about name from json file and its result
    """
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
    """Write a pdf file from html with name resultado_ens.pdf

    Args:
        html (str): html content

    Raises:
        ImportError if weasyprint is not installed
    """
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


def get_system_name():
    """Get name from operative system reading os-release file

    Returns:
        str: name operative system
    """
    os_version = 'ubuntu'
    os_config = read_file('/etc/os-release')
    for line in os_config:
        if line.startswith('NAME'):
            os_version = line.split('=')[1].lower()
            break
    return os_version


def get_real_path_pam_password():
    """Get path from pam password which it depends from operative system

    Returns:
        str: pam.d path for common-password
    """
    path = '/etc/pam.d/common-password'
    if 'red hat' in get_system_name():
        path = '/etc/pam.d/system-auth'
        print_message('ok', 'Sistema Red Hat detectado. Consultando /etc/pam.d/system-auth')
    return path
