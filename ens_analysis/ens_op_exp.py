# -*- coding: utf-8 -*-
import os

from subprocess import Popen, PIPE

from ens_analysis.ens_base import BaseModel
from utils.ens_utils import check_if_process_is_active, get_config_from_file, read_file, execute_command, print_message, get_system_name


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

description_logs = {
    'kern.log': 'Se debe de registrar toda la información del kernel',
    'auth.log': 'Se debe de registrar la información del login en el sistema',
    'sys.log': 'Se debe de registrar la información del sistema',
    'boot.log': 'Se debe de registrar toda la información del arranque del sistema',
    'secure': 'Se debe de registrar la información de autenticación y privilegios',
    'wtmp': 'Se debe de registrar la información de conexión y desconexión de usuarios',
}


class SecurityConfigurations(BaseModel):
    # OP.EXP.2 = CONFIGURACIÓN DE SEGURIDAD
    title = 'OP.EXP.2 - Configuración de seguridad'
    entries_to_display = []

    def _check_grub_protected_by_users_and_password(self):
        grub_protected_by_users = grub_protected_by_users_and_password = False
        content = read_file('/etc/grub.d/00_header')
        if 'set superusers' in content:
            grub_protected_by_users = True
        if 'password' in content or 'password_pbkdf2' in content:
            grub_protected_by_users_and_password = True
        result = 'Correcto' if grub_protected_by_users else 'Incorrecto'
        description = 'La edición del grub debe de estar restringido a ciertos usuarios'
        self.entries_to_display.append(['Edición de grub en el arranque limitado a ciertos usuarios',
                                        'Sí' if grub_protected_by_users else 'No',
                                        result, description])
        result = 'Correcto' if grub_protected_by_users_and_password else 'Incorrecto'
        description = 'La edición del grub debe de estar protegido con contraseña y cifrada si fuese posible'
        self.entries_to_display.append(['Grub protegido con contraseña',
                                        'Sí' if grub_protected_by_users_and_password else 'No',
                                        result, description])

    def _avoid_load_usb_storage(self):
        load_usb_storage = True
        content = read_file('/etc/modprobe.d/no-usb')
        if 'install usb-storage /bin/true' in content:
            load_usb_storage = False
        result = 'Correcto' if not load_usb_storage else 'Incorrecto'
        description = 'La carga de memorias USB debe de estar desactivada por seguridad'
        self.entries_to_display.append(['Detección de memoria usb desactivada',
                                        'Sí' if not load_usb_storage else 'No',
                                        result, description])

    def _check_sysctl_config(self):
        config_data = {}
        lines = get_config_from_file('/etc/sysctl.conf', '#', return_full_content=True)
        for line in lines:
            line_splitted = line.split('=')
            if len(line_splitted) == 2:
                config_data[line_splitted[0].strip()] = line_splitted[1].strip()

        list_properties_to_check = [
            ('Ip Forward activo', 'net.ipv4.ip_forward', '0'),
            ('No permitir paquetes enrutados en origen', 'net.ipv4.conf.default.accept_source_route', '0'),
            ('SYN Cookies activadas', 'net.ipv4.tcp_syncookies', '1'),
            ('¿Aceptar paquetes con opción SRR?', 'net.ipv4.conf.all.accept_source_route', '0'),
            ('¿Aceptar redirecciones (IPv4)? ',
                ['net.ipv4.conf.all.accept_redirects', 'net.ipv4.conf.all.secure_redirects'], ['0', '0']),
            ('¿Registrar paquetes con direcciones imposibles para el kernel?',
                ['net.ipv4.conf.all.log_martians',
                    'net.ipv4.conf.default.accept_source_route',
                    'net.ipv4.conf.default.accept_redirects'
                    'net.ipv4.conf.default.secure_redirects'],
                ['1', '0', '0', '0']),
            ('Ignorar todas las peticiones ICPM enviadas a través de broadcast/multicast', 'net.ipv4.icmp_echo_ignore_broadcasts', '1'),
            ('Protección SYN-flood activada', 'net.ipv4.tcp_synack_retries', '5'),
            ('Protección ante mensajes de error mal formateados', 'net.ipv4.icmp_ignore_bogus_error_responses', '1'),
            ('RFC 1337 fix', 'net.ipv4.tcp_rfc1337', '1',),
            ('Funcionamiento como router',
                ['net.ipv4.conf.all.send_redirects',
                    'net.ipv4.conf.default.send_redirects'], ['0', '0']),
            ('Reverse Path Filtering activo',
                ['net.ipv4.conf.default.rp_filter', 'net.ipv4.conf.all.rp_filter'], ['1', '1']),
            ('Funciones SysRq desactivadas', 'kernel.sysrq', '0'),
            ('Protección ExecShield activa',
                ['kernel.exec-shield', 'kernel.randomize_va_space'],
                ['2', '2']),
            ('Reinicio en caso de error interno del sistema', 'kernel.panic', '10'),
            ('Protección de vulnerabilidades TOCTOU (Hardlinks)', 'fs.protected_hardlinks', '1'),
            ('Protección de vulnerabilidades TOCTOU (Symlinks)', 'fs.protected_symlinks', '1')
        ]

        for property in list_properties_to_check:
            title = property[0]
            configured = False
            if isinstance(property[1], list):
                for index in range(len(property[1])):
                    field_to_check = property[1][index]
                    value_expected = property[2][index]
                    if field_to_check in config_data and config_data[field_to_check] == value_expected:
                        configured = True
                    else:
                        configured = False
                    if configured is False:
                        break
            else:
                configured = False
                if property[1] in config_data and config_data[property[1]] == property[2]:
                    configured = True
            result = 'Correcto' if configured else 'Incorrecto'
            description = property[3] if len(property) == 4 else ''
            self.entries_to_display.append([title, result, result, description])

    def _check_selinux(self):
        selinux_enabled = False
        config_selinux = get_config_from_file('/etc/selinux/config', '#')
        if 'SELINUX' in config_selinux and config_selinux['SELINUX'] != 'disabled':
            selinux_enabled = True
        result = 'Correcto' if selinux_enabled else 'Incorrecto'
        description = 'El módulo SELinux (Módulo de seguridad para el kernel linux) debe de estar activo'
        self.entries_to_display.append(['SELinux activo',
                                        'Sí' if selinux_enabled else 'No',
                                        result, description])

    def get_params(self):
        print_message('ok', 'Analizando las configuraciones de seguridad.')
        config = {
            0: [
                self._check_grub_protected_by_users_and_password,
                self._avoid_load_usb_storage,
                self._check_selinux,
                self._check_sysctl_config,
            ],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de las configuraciones de seguridad.')


class ChangeManagement(BaseModel):
    # OP.EXP.5 = GESTIÓN DE CAMBIOS
    title = 'OP.EXP.5 - Gestion de Cambios'
    entries_to_display = []

    def __get_num_updates(self):
        self.package_updates = self.security_updates = 0
        os_name = get_system_name()
        if 'red hat' in os_name:
            package_updates = execute_command('yum list updates | wc -l')
            if 'ERROR' in package_updates:
                self.package_updates = 0
            else:
                self.package_updates = package_updates
            security_updates = execute_command('yum list security | wc -l')
            if 'ERROR' in security_updates:
                self.security_updates = 0
            else:
                self.security_updates = security_updates
        else:
            command = Popen(["/usr/lib/update-notifier/apt-check"], stdout=PIPE, stderr=PIPE)
            out, err = command.communicate()
            if err:
                if isinstance(err, bytes):
                    err = err.decode('utf-8')
                updates = err.split(';')
                self.package_updates = updates[0]
                self.security_updates = updates[1]

    def _parse_content_updates(self):
        self.__get_num_updates()
        if int(self.package_updates):
            package_message = 'Hay %s actualizaciones pendientes' % self.package_updates
            package_result = 'Incorrecto'
        else:
            package_message = 'No hay actualizaciones pendientes'
            package_result = 'Correcto'

        if int(self.security_updates):
            security_message = 'Hay %s actualizaciones de seguridad pendientes' % self.security_updates
            security_result = 'Incorrecto'
        else:
            security_message = 'No hay actualizaciones de seguridad pendientes'
            security_result = 'Correcto'

        self.entries_to_display.append(['Actualizaciones del sistema', package_message, package_result, 'Todas las actualizacines del sistema deberían de estar instaladas'])
        self.entries_to_display.append(['Actualizaciones de seguridad', security_message, security_result, 'Todas las actualizaciones de seguridad deberían de estar instaladas'])

    def __get_firewalls(self):
        self.firewalls = []
        list_firewalls = self.config_data.get("firewalls", ["iptables", "ufw", "firewalld", "nftables"])
        for firewall in list_firewalls:
            if check_if_process_is_active(firewall):
                self.firewalls.append(str(firewall))
        return self.firewalls

    def _parse_content_firewalls(self):
        self.__get_firewalls()
        if self.firewalls:
            firewall_message = ', '.join(self.firewalls)
            firewall_result = 'Correcto'
        else:
            firewall_message = 'No se ha detectado ningun firewall activo'
            firewall_result = 'Incorrecto'
        description = 'Debe de existir un firewall activo en el sistema, de entre los siguientes: iptables, ufw, firewalld, nftables'
        self.entries_to_display.append(['Firewall del sistema', firewall_message, firewall_result, description])

    def get_params(self):
        print_message('ok', 'Analizando la gestión de cambios.')
        config = {
            0: [
                self._parse_content_updates,
                self._parse_content_firewalls,
            ],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de la gestión de cambios.')


class ProtectionAgainstHarmfulCode(BaseModel):
    # OP.EXP.6 = Protección frente a código dañino
    title = 'OP.EXP.6 - Protección frente a código dañino'
    entries_to_display = []

    def _get_antivirus(self):
        self.antivirus = []
        list_antivirus = self.config_data.get("antivirus", ["clamav", "clamtk", "sophos", "comodo", "fprot"])
        for antivirus in list_antivirus:
            if check_if_process_is_active(antivirus):
                self.antivirus.append(antivirus)
        return self.antivirus

    def _parse_content_antivirus(self):
        self._get_antivirus()
        if self.antivirus:
            antivirus_message = 'Se han detectado los siguientes antivirus activos: ' + \
                ', '.join(self.antivirus)
            antivirus_result = 'Correcto'
        else:
            antivirus_message = 'No hay ningún antivirus activo'
            antivirus_result = 'Incorrecto'
        description = 'Debe de existir un antivirus en el sistema, de entre las siguientes posibilidades: clamav, clamtk, sophos, comodo, fprot'
        self.entries_to_display.append(['Antivirus', antivirus_message, antivirus_result, description])

    def get_params(self):
        print_message('ok', 'Analizando la protección frente a código dañino.')
        config = {
            0: [
                self._parse_content_antivirus,
            ],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de la protección frente a código dañino.')


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
            self.params_logs.append([name_logs[log], log_message, log_result, description_logs[log]])
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

        log_can_not_read_title = 'Lectura de logs al resto de usuarios'
        log_can_not_read_message = 'El resto de usuarios no puede leer los logs del sistema'
        if not list_log_can_not_read:
            log_can_not_read_message = 'El resto de usuarios pueden leer los logs del sistema'
        self.log_permissions_parsed.append(
            [log_can_not_read_title, log_can_not_read_message,
                'Correcto' if list_log_can_not_read else 'Incorrecto', 'Solo los administradores deberían poder consultar los logs anteriores'])

        log_can_not_edit_or_execute_title = 'Modificación de logs del resto de usuario'
        log_can_not_edit_or_execute_message = 'El resto de usuarios no puede modificar los logs del sistema'
        if not list_log_can_not_edit_or_execute:
            log_can_not_edit_or_execute_message = 'El resto de usuarios pueden modificar los logs del sistema'
        self.log_permissions_parsed.append(
            [log_can_not_edit_or_execute_title, log_can_not_edit_or_execute_message,
                'Correcto' if list_log_can_not_edit_or_execute else 'Incorrecto', 'Nadie debería de poder modificar los logs anteriores'])

        return self.log_permissions_parsed

    def _get_log_properties(self):
        self.log_properties = dict()
        if self.logs:
            for log_name in self.logs:
                command = 'ls -l {0}'.format(default_logs[log_name])
                response_command = execute_command(command)
                response_command = response_command.splitlines()
                for line in response_command:
                    if log_name in line:
                        props = " ".join(line.split())
                        all_props = self.log_properties.get(log_name, [])
                        all_props.append(props)
                        self.log_properties[log_name] = all_props
        return self.log_properties

    def get_params(self):
        print_message('ok', 'Analizando el registro de actividades de usuario y protección de los mismos.')
        config = {
            0: [
                self._check_logs,
                self._check_log_properties,
                self._parse_content_logs,
                self._parse_content_permissions,
            ],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin del registro de actividades de usuario y protección de los mismos.')

    def get_html_exp8(self):
        percentage = self.get_results(self.params_logs)[0]
        return self.get_html(title=self.title_8, percentage=percentage, entries=self.params_logs)

    def get_html_exp10(self):
        percentage = self.get_results(self.log_permissions_parsed)[0]
        return self.get_html(title=self.title_10, percentage=percentage, entries=self.log_permissions_parsed)
