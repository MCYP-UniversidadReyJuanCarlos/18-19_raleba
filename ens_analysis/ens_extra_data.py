# -*- coding: utf-8 -*-
import json
import sys

from ens_analysis.ens_base import BaseModel
from utils.ens_utils import get_config_from_file, execute_command


class SystemInfo(BaseModel):

    def __html_header(self, id_html, title):
        html = """
        <div class="panel-group" style='margin-bottom: 0px'>
            <div class="panel panel-default"><div class="panel-heading">
                <h4 class="panel-title">
                    <a class="title_a" data-toggle="collapse" href='#{0}'>
                        {1}
                    </a>
                </h4>
            </div>
            <div id="{0}" class="panel-collapse collapse">
                <div class="panel-body">
                    <table style="width: 100%">
                        <tbody>
        """.format(id_html, title)
        return html

    def memory_info(self):
        command = "free"
        memory_info = []
        command_response = execute_command(command).splitlines()
        for mem_info in command_response:
            list_mem_info = mem_info.split()
            if len(list_mem_info) != 7:
                continue
            memory_info.append(list_mem_info)
        return memory_info

    def get_html_memory_info(self):
        html = self.__html_header('memoryinfo', 'Información de la memoria')
        memory_data = self.memory_info()
        for memory in memory_data:
            name = 'RAM' if "Mem" in memory[0] else memory[0]
            memory_size = memory[1]
            if memory_size.isdigit():
                memory_size = float(memory_size) / (1024 * 1024)
                memory_size = '{0:.2f}'.format(memory_size) + ' GB'
            html += """
                <tr>
                    <th style='padding-right: 10px; vertical-align: top; width: 40%;'>
                        {0}
                    </th>
                    <th style='padding-right: 10px; vertical-align: top;'>
                        {1}
                    </th>
                </tr>""".format(name, memory_size)
        html += """</tbody></table></div></div></div>"""
        return html

    def system_info(self):
        system_info = {}
        command = 'lsb_release -a'
        command_response = execute_command(command).splitlines()
        for line in command_response:
            if ':' in line:  # Avoid this message: No LSB modules are available.
                param_splitted = line.split(':')
                system_info[param_splitted[0]] = param_splitted[1]
        return system_info

    def get_html_system_info(self):
        html = self.__html_header('systeminfo', 'Información del sistema operativo')
        system_info_data = self.system_info()
        info_to_parse = {
            'Distributor ID': 'Id del distribuidor',
            'Description': 'Descripción',
            'Release': 'Versión',
            'Codename': 'Nombre Clave'
        }
        for system_info in system_info_data:
            html += """
            <tr>
                <th style='padding-right: 10px; vertical-align: top; width: 40%;'>
                    {0}
                </th>
                <th style='padding-right: 10px; vertical-align: top;'>
                    {1}
                </th>
            </tr>""".format(info_to_parse.get(system_info, system_info), system_info_data.get(system_info))
        html += """</tbody></table></div></div></div>"""
        return html

    def kernel_version(self):
        command = 'uname -r'
        return execute_command(command)

    def get_html_kernel(self):
        html = self.__html_header('kernelinfo', 'Información del kernel')
        kernel_info = self.kernel_version()
        html += """
            <tr>
                <th style='padding-right: 10px; vertical-align: top; width: 40%;'>
                    {0}
                </th>
                <th style='padding-right: 10px; vertical-align: top;'>
                    {1}
                </th>
            </tr>
        """.format('Versión del kernel', kernel_info)
        html += """</tbody></table></div></div></div>"""
        return html

    def network_info(self):
        interfaces = {}
        command = 'ifconfig'
        command_response = execute_command(command).split('\n\n')
        for network_interface in command_response:
            if not network_interface:
                continue
            network_params = {}
            network_interface = network_interface.replace('\n', '')
            interface = network_interface.split(':')
            interface_name = interface[0]
            data_config = ':'.join(interface[1:]).split()
            fields_to_get = ['inet', 'broadcast', 'inet6', 'ether', 'netmask']
            for field in fields_to_get:
                if field in data_config:
                    pos_field = data_config.index(field)
                    network_params[field] = data_config[pos_field + 1]
            interfaces[interface_name] = network_params
        return interfaces

    def get_html_network_info(self):
        interfaces = self.network_info()
        fields_name = {
            'inet': 'IP',
            'inet6': 'IPv6',
            'broadcast': 'Broadcast',
            'netmask': 'Máscara de red',
            'ether': 'MAC'
        }

        html = """
        <div class="panel-group" style='margin-bottom: 0px'>
            <div class="panel panel-default"><div class="panel-heading">
                <h4 class="panel-title">
                    <a class="title_a" data-toggle="collapse" href='#{0}'>
                        {1}
                    </a>
                </h4>
            </div>
            <div id="{0}" class="panel-collapse collapse">
                """.format('networkinfo', 'Información de las interfaces de red')

        for interface in interfaces:
            html += """
                <div class="panel-body">
                    <div class="div_title_top">Interfaz: {0}</div>
                    <table style="width: 100%; margin-left: 2%;">
                        <tbody>
            """.format(interface)
            for field in interfaces[interface]:
                field_name = fields_name.get(field)
                html += """
                    <tr>
                        <th style='padding-right: 10px; vertical-align: top; width: 40%;'>
                            {0}
                        </th>
                        <th style='padding-right: 10px; vertical-align: top;'>
                            {1}
                        </th>
                    </tr>""".format(field_name, interfaces[interface].get(field))
            html += "</tbody></table></div>"
        html += "</div></div>"
        return html

    def hd_info(self):
        hd_info = []
        command = 'df -kh'
        command_response = execute_command(command).splitlines()
        for device in command_response:
            params_hd = device.split()
            if len(params_hd) != 6:
                continue
            hd_info.append(params_hd)
        return hd_info

    def get_html_hd_info(self):
        html = self.__html_header('hdinfo', 'Información de uso del HD')
        html += """
            <tr>
                <th style='padding-right: 10px; vertical-align: top; width: 20%;'>
                    <strong>Nom. del sistema de archivos</strong>
                </th>
                <th style='padding-right: 10px; vertical-align: top; width: 20%;'>
                    <strong>Tamaño</strong>
                </th>
                <th style='padding-right: 10px; vertical-align: top; width: 20%;'>
                    <strong>Uso</strong>
                </th>
                <th style='padding-right: 10px; vertical-align: top; width: 40%;'>
                    <strong>Punto de montaje</strong>
                 </th>
            </tr>"""
        hd_info = self.hd_info()
        for hd in hd_info:
            html += """
                <tr>
                    <th style='padding-right: 10px; vertical-align: top; width: 20%;'>
                        {0}
                    </th>
                    <th style='padding-right: 10px; vertical-align: top; width: 20%;'>
                        {1}
                    </th>
                    <th style='padding-right: 10px; vertical-align: top; width: 20%;'>
                        {2}
                    </th>
                    <th style='padding-right: 10px; vertical-align: top; width: 40%;'>
                        {3}
                    </th>
                </tr>""".format(hd[0], hd[1], hd[4], hd[5])
        html += "</tbody></table></div></div></div>"
        return html

    def get_html(self):
        html = """
            <div class="div_title_top">
                <span>
                    Información del sistema
                </span>
            </div>
        """
        html += self.get_html_system_info()
        html += self.get_html_kernel()
        html += self.get_html_memory_info()
        html += self.get_html_hd_info()
        html += self.get_html_network_info()
        html = html.replace('\n', '')
        return html


class ExtraConfigJson(BaseModel):

    list_config_parsed = []

    def __init__(self, json_file_path):
        self.json_file_path = json_file_path
        self.get_params()

    def get_params(self):
        json_data = dict_config = {}
        with open(self.json_file_path, 'r') as file:
            json_data = json.load(file)
        for key in json_data:
            configs_to_check = json_data[key]
            for config in configs_to_check:
                if len(config) != 6:
                    continue
                path_to_check = config[0]
                property = config[1]
                lines_to_ignore = config[2]
                separator = config[3]
                name_in_report = config[4]
                expected_value = config[5]
                if path_to_check not in dict_config:
                    config_file = get_config_from_file(path_to_check, lines_to_ignore, True)
                    dict_config[path_to_check] = config_file
                    params_file_config = {}
                    for line in config_file:
                        if separator:
                            line_splitted = line.split(separator)
                        else:
                            line_splitted = line.split()
                        if line_splitted[0] in params_file_config:
                            actual_values_for_key = params_file_config[line_splitted[0]]
                            actual_values_for_key.append(''.join(line_splitted[1:]))
                            params_file_config[line_splitted[0]] = actual_values_for_key
                        else:
                            params_file_config[line_splitted[0]] = [''.join(line_splitted[1:])]
                    dict_config[path_to_check] = params_file_config
                result = 'Incorrecto'
                if property in dict_config:
                    for field in dict_config[property]:
                        if expected_value in field:
                            result = 'Correcto'
                        else:
                            result = 'Incorrecto'
                            break
                self.list_config_parsed.append(
                    ('[' + key + '] ' + name_in_report, result)
                )

    def get_html(self):
        html = """
            <div class="panel-group" style='margin-bottom: 0px'>
                <div class="panel panel-default"><div class="panel-heading">
                    <h4 class="panel-title">
                        <a class="title_a" data-toggle="collapse" href='#ConfiguracionExtra'>
                            Configuración extra
                        </a>
                    </h4>
                </div><div id="ConfiguracionExtra" class="panel-collapse collapse">
            <div class="panel-body">
            <table style="width: 100%">
                <thead>
                    <tr>
                        <th style="width: 80%; padding-right: 10px;">
                            Nombre
                        </th>
                        <th style="width: 20%;">
                            Resultado
                        </th>
                    </tr>
                </thead>
                <tbody>
        """
        for config in self.list_config_parsed:
            name = config[0]
            if sys.version_info[0] < 3:
                name = config[0].encode('utf-8')
            color = 'red'
            if config[1] == 'Correcto':
                color = 'green'
            html += """
                <tr><th style='padding-right: 10px; vertical-align: top;'>
                    <strong>{0}</strong>
                </th><th style='padding-right: 10px; vertical-align: top; color: {2} !important'>
                    {1}
                </th></tr>""".format(name, config[1], color)
        html += """</tbody></table></div></div></div></div>"""
        return html


class OpenPortsInformation(BaseModel):

    list_connections = []

    def __init__(self):
        self.get_params()

    def get_params(self):
        command = 'netstat -lntu'
        response_splitted = execute_command(command).splitlines()
        for line in response_splitted:
            info = line.split()
            if info and info[0][:3] in ['tcp', 'udp']:
                ip = info[3][:info[3].rfind(':')]
                port = info[3][info[3].rfind(':') + 1:]
                self.list_connections.append(
                    (info[0], ip, port)
                )

    def get_html(self):
        html = """
            <div class="panel-group" style='margin-bottom: 0px'>
                <div class="panel panel-default"><div class="panel-heading">
                    <h4 class="panel-title">
                        <a class="title_a" data-toggle="collapse" href='#PuertosIniciados'>
                            Puertos activos
                        </a>
                    </h4>
                </div><div id="PuertosIniciados" class="panel-collapse collapse">
            <div class="panel-body">
            <table style="width: 100%">
                <thead>
                    <tr>
                        <th style="width: 40%; padding-right: 10px;">
                            Protocolo
                        </th>
                        <th style="width: 40%; padding-right: 10px;">
                            Ip
                        </th>
                        <th style="width: 20%;">
                            Puerto
                        </th>
                    </tr>
                </thead>
                <tbody>
        """
        for port in self.list_connections:
            html += """
                <tr><th style='padding-right: 10px; vertical-align: top;'>
                    {0}
                </th><th style='padding-right: 10px; vertical-align: top;'>
                    {1}
                </th><th style='padding-right: 10px; vertical-align: top;'>
                    {2}
                </th></tr>""".format(port[0], port[1], port[2])
        html += """</tbody></table></div></div></div></div>"""
        return html


class ServicesOnBoot(BaseModel):

    list_services_to_show = []

    def get_params(self):
        command = 'systemctl list-units --type service'
        response_splitted = execute_command(command).splitlines()
        for line in response_splitted:
            info = line.split()
            if info and info[0].endswith('.service'):
                self.list_services_to_show.append(
                    (info[0], ' '.join(info[4:]))
                )

    def get_html(self):
        html = """
            <div class="panel-group" style='margin-bottom: 0px'>
                <div class="panel panel-default"><div class="panel-heading">
                    <h4 class="panel-title">
                        <a class="title_a" data-toggle="collapse" href='#ServiciosIniciadosConElSistema'>
                            Servicios Iniciados Con el sistema
                        </a>
                    </h4>
                </div><div id="ServiciosIniciadosConElSistema" class="panel-collapse collapse">
            <div class="panel-body">
            <table style="width: 100%">
                <thead>
                    <tr>
                        <th style="width: 40%; padding-right: 10px;">
                            Servicio
                        </th>
                        <th style="width: 60%;">
                            Descripción
                        </th>
                    </tr>
                </thead>
                <tbody>
        """
        for service in self.list_services_to_show:
            html += """
                <tr><th style='padding-right: 10px; vertical-align: top;'>
                    {0}
                </th><th style='padding-right: 10px; vertical-align: top;'>
                    {1}
                </th></tr>""".format(service[0], service[1])
        html += """</tbody></table></div></div></div></div>"""
        return html
