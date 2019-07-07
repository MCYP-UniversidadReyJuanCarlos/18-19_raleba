# -*- coding: utf-8 -*-
import logging
import os

from subprocess import Popen, PIPE

from utils import check_if_process_is_active

from base import BaseModel


log = logging.getLogger(name=__name__)

default_logs = {
    'kern.log': '/var/log/',
    'auth.log': '/var/log/',
    'sys.log': '/var/log/',
    'boot.log': '/var/log/',
    'secure': '/var/log/',
    'wtmp': '/var/log/',
}

name_logs = {
    'kern.log': 'Log del kernel',
    'auth.log': 'Log de login en el sistema',
    'sys.log': 'Log del sistema',
    'boot.log': 'Log de arranque del sistema',
    'secure': 'Log de autenticación y privilegios',
    'wtmp': 'Log de conexión y desconexión de usuarios',
}


class ChangeManagement(BaseModel):
    # OP.EXP.5 = GESTIÓN DE CAMBIOS
    title = 'OP.EXP.5 - Gestión de Cambios'
    entries_to_display = []

    def get_params(self):
        self._get_num_updates()
        self._parse_content_updates()
        self._get_firewalls()
        self._parse_content_firewalls()

    def _get_num_updates(self):
        self.package_updates = self.security_updates = 0
        command = Popen(["/usr/lib/update-notifier/apt-check"],
                        stdout=PIPE, stderr=PIPE)
        out, err = command.communicate()
        if err:
            updates = err.split(';')
            self.package_updates = updates[0]
            self.security_updates = updates[1]

    def _parse_content_updates(self):
        self.package_updates_control = self.security_updates_control = False

        if int(self.package_updates):
            package_message = 'Hay %s actualizaciones pendientes' % self.package_updates
            package_result = 'Incorrecto'
        else:
            package_message = 'No hay actualizaciones pendientes'
            package_result = 'Correcto'
            self.package_updates_control = True
        self.package_updates_resp = [
            'Actualizaciones del sistema', package_message, package_result]

        if int(self.security_updates):
            security_message = 'Hay %s actualizaciones de seguridad pendientes' % self.security_updates
            security_result = 'Incorrecto'
        else:
            security_message = 'No hay actualizaciones de seguridad pendientes'
            security_result = 'Correcto'
            self.security_updates_control = True
        self.security_updates_resp = [
            'Actualizaciones de seguridad', security_message, security_result]

        self.entries_to_display.append(self.package_updates_resp)
        self.entries_to_display.append(self.security_updates_resp)
        return self.package_updates_resp, self.security_updates_resp

    def _get_firewalls(self):
        self.firewalls = []
        list_firewalls = ["iptables", "ufw"]
        for firewall in list_firewalls:
            if check_if_process_is_active(firewall):
                self.firewalls.append(firewall)
        return self.firewalls

    def _parse_content_firewalls(self):
        if self.firewalls:
            firewall_message = 'Se ha detectado los siguientes firewalls activos: ' + \
                ', '.join(self.firewalls)
            firewall_result = 'Correcto'
        else:
            firewall_message = 'No se ha detectado ningún firewall activo'
            firewall_result = 'Incorrecto'
        self.firewall_resp = ['Firewall del sistema', firewall_message, firewall_result]
        self.entries_to_display.append(self.firewall_resp)


class ProtectionAgainstHarmfulCode(BaseModel):
    # OP.EXP.6 = Protección frente a código dañino
    title = 'OP.EXP.6 - Protección frente a código dañino'
    entries_to_display = []

    def _get_antivirus(self):
        self.antivirus = []
        list_antivirus = ["clamav", "clamtk", "sophos", "comodo", "fprot"]
        for each_antivirus in list_antivirus:
            if check_if_process_is_active(each_antivirus):
                self.antivirus.append(each_antivirus)
        return self.antivirus

    def _parse_content_antivirus(self):
        if self.antivirus:
            antivirus_message = 'Se han detectado los siguientes antivirus activos: ' + \
                ', '.join(self.antivirus)
            antivirus_result = 'Correcto'
        else:
            antivirus_message = 'No hay ningún antivirus activo'
            antivirus_result = 'Incorrecto'
        self.antivirus_parsed = ['Antivirus', antivirus_message, antivirus_result]
        self.entries_to_display.append(self.antivirus_parsed)

    def get_params(self):
        self._get_antivirus()
        self._parse_content_antivirus()


class RegisterActivityLogs(BaseModel):
    # OP.EXP.8 = Registro de actividades del usuario
    # OP.EXP.10 = Protección de los registros de actividad

    title_8 = 'OP.EXP.8 - Registro de actividades del usuario'
    title_10 = 'OP.EXP.10 - Protección de los registros de actividad'

    def _check_logs(self):
        self.logs = dict()
        for log_name in default_logs:
            if os.path.exists(default_logs[log_name]):
                self.logs[log_name] = True
            else:
                self.logs[log_name] = False
        return self.logs

    def _parse_content_logs(self):
        self.params_logs = []
        for log in self.logs:
            log_message = log_result = 'Correcto' if self.logs[log] else 'Incorrecto'
            self.params_logs.append([name_logs[log], log_message, log_result])
        return self.params_logs

    def _check_log_properties(self):
        self.log_permissions = dict()
        logs_properties = self._get_log_properties()
        for log_name in logs_properties:
            permissions = logs_properties[log_name][0].split()[0][7:]
            not_can_edit_or_execute = True
            not_can_read_log = True
            if permissions[1] != '-' or permissions[2] != '-':
                not_can_edit_or_execute = False
            if permissions[0] != '-':
                not_can_read_log = False
            self.log_permissions[log_name] = (
                not_can_read_log, not_can_edit_or_execute)

        return self.log_permissions

    def _parse_content_permissions(self):
        self.log_permissions_parsed = []
        list_log_can_not_read = list_log_can_not_edit_or_execute = []
        for log_permission in self.log_permissions:
            if not log_permission[0]:
                list_log_can_not_read.append(log_permission)
            if not log_permission[1]:
                list_log_can_not_edit_or_execute.append(log_permission)

        if list_log_can_not_read:
            self.log_permissions_parsed.append(['Lectura de logs al resto de usuarios', 'El resto de usuarios no puede leer los logs del sistema', 'Correcto'])
        else:
            self.log_permissions_parsed.append(['Lectura de logs al resto de usuarios', 'El resto de usuarios pueden leer los logs del sistema', 'Incorrecto'])

        if list_log_can_not_edit_or_execute:
            self.log_permissions_parsed.append(['Modificación de logs del resto de usuarios', 'El resto de usuarios no puede modificar los logs del sistema', 'Correcto'])
        else:
            self.log_permissions_parsed.append(['Modificación de logs del resto de usuarios', 'El resto de usuarios pueden modificar los logs del sistema', 'Incorrecto'])

        return self.log_permissions_parsed

    def _get_log_properties(self):
        self.log_properties = dict()
        if self.logs:
            for log_name in self.logs:
                command = Popen(
                    ["ls", "-l", default_logs[log_name]], stdout=PIPE, stderr=PIPE)
                suc, err = command.communicate()
                result = str(suc).split("\n")
                for line in result:
                    if log_name in line:
                        props = " ".join(line.split())
                        all_props = self.log_properties.get(log_name, [])
                        all_props.append(props)
                        self.log_properties[log_name] = all_props
        return self.log_properties

    def get_params(self):
        self._check_logs()
        self._check_log_properties()
        self._parse_content_logs()
        self._parse_content_permissions()

    def get_html_exp8(self):
        html = """
            <div class="panel-group" style='margin-bottom: 0px'>
                <div class="panel panel-default"><div class="panel-heading">
                    <h4 class="panel-title">
                        <a data-toggle="collapse" href='#""" + self.title_8.replace(' ', '').replace('-', '').replace('.', '') + """'>
                            <strong>""" + self.title_8 + """</strong>
                        </a>
                    </h4>
                </div><div id=""" + self.title_8.replace(' ', '').replace('-', '').replace('.', '') + """ class="panel-collapse collapse">
            <div class="panel-body">
            <table style="width: 100%">
                <thead>
                    <tr>
                        <th style="width: 20%; padding-right: 10px; font-size: 18px; font-weight: bold;">
                            Entrada
                        </th>
                        <th style="width: 20%; padding-right: 10px; font-size: 18px; font-weight: bold;">
                            Notas
                        </th>
                        <th style="width: 20%; text-align: center; font-size: 18px; font-weight: bold;">
                            Resultado
                        </th>
                    </tr>
                </thead>
            <tbody>
        """
        for entry in self.params_logs:
            color = 'red'
            if entry[2] == 'Correcto':
                color = 'green'
            html += "<tr><th style='padding-right: 10px; vertical-align: top;'>%s</th><th style='padding-right: 10px; vertical-align: top; color:%s'>%s</th><th style='text-align: center; vertical-align: top; color:%s'><strong>%s</strong></th></tr>" % (entry[0], color, entry[1], color, entry[2])
        html += """</tbody></table></div></div></div></div>"""
        return html

    def get_html_exp10(self):
        html = """
            <div class="panel-group" style='margin-bottom: 0px'>
                <div class="panel panel-default"><div class="panel-heading">
                    <h4 class="panel-title">
                        <a data-toggle="collapse" href='#""" + self.title_10.replace(' ', '').replace('-', '').replace('.', '') + """'>
                            <strong>""" + self.title_10 + """</strong>
                        </a>
                    </h4>
                </div><div id=""" + self.title_10.replace(' ', '').replace('-', '').replace('.', '') + """ class="panel-collapse collapse">
            <div class="panel-body">
            <table style="width: 100%">
                <thead>
                    <tr>
                        <th style="width: 20%; padding-right: 10px; font-size: 18px; font-weight: bold;">
                            Entrada
                        </th>
                        <th style="width: 20%; padding-right: 10px; font-size: 18px; font-weight: bold;">
                            Notas
                        </th>
                        <th style="width: 20%; text-align: center; font-size: 18px; font-weight: bold;">
                            Resultado
                        </th>
                    </tr>
                </thead>
            <tbody>
        """
        for entry in self.log_permissions_parsed:
            color = 'red'
            if entry[2] == 'Correcto':
                color = 'green'
            html += "<tr><th style='padding-right: 10px; vertical-align: top;'>%s</th><th style='padding-right: 10px; vertical-align: top; color:%s'>%s</th><th style='text-align: center; vertical-align: top; color:%s'><strong>%s</strong></th></tr>" % (entry[0], color, entry[1], color, entry[2])
        html += """</tbody></table></div></div></div></div>"""
        return html
