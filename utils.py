import os
import subprocess
from sys import platform

from subprocess import Popen, PIPE


def check_if_linux_system():
    return True if platform in ["linux", "linux2"] else False


def check_if_is_root():
    return True if os.getuid() == 0 else False


def check_if_package_installed(package):
    call_result = subprocess.call(["which", str(package)])
    return True if call_result == 0 else False


def check_if_process_is_active(process):
    command = Popen(["service", str(process), "status"],
                    stdout=PIPE, stderr=PIPE)
    out, err = command.communicate()
    if out:
        return True
    else:
        return False


def get_config_from_file(path_file_to_check, ignore_lines_start_with, return_full_content=False):
    config = dict()
    file = open(path_file_to_check, 'r')
    content = file.read().splitlines()
    config_lines = [text for text in content if text and not text.startswith(ignore_lines_start_with)]
    if return_full_content:
        return content
    for line in config_lines:
        line = line.replace("\t", " ")
        params = line.split(" ")
        if params:
            config[params[0]] = ''.join(params[1:])
    return config


def full_html(html):
    full_html = """
        <!DOCTYPE html>
        <html lang="es">
           <head>
              <meta charset="utf-8">
              <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/css/bootstrap.min.css">
              <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.0/jquery.min.js"></script>
              <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/js/bootstrap.min.js"></script>
              <style>
                th {
                    font-weight: inherit;
                }
              </style>
           </head>
           <body>
                <div class="well" style="width: 90%; margin-left: 5%;">
    """
    full_html += html
    full_html += """
        </div></body></html>
    """
    return full_html
