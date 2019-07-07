# -*- coding: utf-8 -*-
import logging
import os

from utils import *

from base import BaseModel

log = logging.getLogger(name=__name__)


class AuthenticationMechanisms(BaseModel):
    # OP.ACC.5
    title = 'OP.ACC.5 - Mecanismos de Autenticación'
    entries_to_display = []

    def _get_pass_min_days(self):
        self.pass_min_days = None
        config_file = get_config_from_file('/etc/login.defs', '#')
        if config_file and 'PASS_MIN_DAYS' in config_file:
            self.pass_min_days = config_file.get('PASS_MIN_DAYS')
        self.entries_to_display.append(['Vigencia mínima de la contraseña',
                                        self.pass_min_days if self.pass_min_days else 'Indeterminado',
                                        'Correcto' if self.pass_min_days else 'Incorrecto'])
        return self.pass_min_days

    def _get_pass_max_days(self):
        self.pass_max_days = None
        config_file = get_config_from_file('/etc/login.defs', '#')
        if config_file and 'PASS_MAX_DAYS' in config_file:
            self.pass_max_days = config_file.get('PASS_MAX_DAYS')
        self.entries_to_display.append(['Vigencia máxima de la contraseña',
                                        self.pass_max_days if self.pass_max_days else 'Indeterminado',
                                        'Correcto' if self.pass_max_days else 'Incorrecto'])
        return self.pass_max_days

    def _get_pass_warn_age(self):
        self.pass_warn_days = None
        config_file = get_config_from_file('/etc/login.defs', '#')
        if config_file and 'PASS_WARN_AGE' in config_file:
            self.pass_warn_days = config_file.get('PASS_WARN_AGE')
        self.entries_to_display.append(['Aviso de fin de vigencia de la contraseña',
                                        self.pass_warn_days if self.pass_warn_days else 'Indeterminado',
                                        'Correcto' if self.pass_warn_days else 'Incorrecto'])
        return self.pass_warn_days

    def _get_complexity_pass(self):
        self.complexity_pass = False
        config_file = get_config_from_file('/etc/pam.d/common-password', '#')
        if config_file and 'password' in config_file:
            password_config = config_file.get('password')
            if ('ucredit=-1' in password_config and 'lcredit=-2' in password_config) and ('dcredit=-1' in password_config and 'ocredit=-1' in password_config):
                self.complexity_pass = True
        self.entries_to_display.append(['Complejidad de la contraseña',
                                        'Hay definida una política de complejidad adecuada' if self.pass_warn_days else 'No hay definida una política de seguridad adecuada',
                                        'Correcto' if self.pass_warn_days else 'Incorrecto'])
        return self.complexity_pass

    def _get_min_length_pass(self):
        self.min_length_pass = None
        config_file = get_config_from_file('/etc/pam.d/common-password', '#')
        if config_file and 'password' in config_file:
            password_config = config_file.get('password')
            params = password_config.split(' ')
            for param in params:
                if 'minlen' in param:
                    self.min_length_pass = param.split('=')[1]
                    break
        self.entries_to_display.append(['Longitud mínima de la contraseña',
                                        self.min_length_pass if self.min_length_pass else 'Indeterminado',
                                        'Correcto' if self.min_length_pass and self.min_length_pass else 'Incorrecto'])
        return self.min_length_pass

    def _get_avoid_use_same_pass(self):
        self.avoid_use_same_pass = None
        config_file = get_config_from_file('/etc/pam.d/common-password', '#')
        if config_file and 'password' in config_file:
            password_config = config_file.get('password')
            params = password_config.split(' ')
            for param in params:
                if 'remember' in param:
                    self.min_length_pass = param.split('=')[1]
                    break
        self.entries_to_display.append(['Historial de contraseña (Número de contraseñas anteriores para repetir la misma contraseña)',
                                        self.avoid_use_same_pass if self.avoid_use_same_pass else 'Indeterminado',
                                        'Correcto' if self.avoid_use_same_pass and self.avoid_use_same_pass > 7 else 'Incorrecto'])
        return self.avoid_use_same_pass

    def _get_num_days_inactive_account(self):
        self.num_days_inactive_account = None
        config_file = get_config_from_file('/etc/pam.d/common-password', '#')
        if config_file and 'password' in config_file:
            password_config = config_file.get('password')
            params = password_config.split(' ')
            for param in params:
                if 'INACTIVE' in param:
                    self.num_days_inactive_account = param.split('=')[1]
                    break
        self.entries_to_display.append(['Inactividad de cuenta (Número de días sin actividad para desactivar la cuenta)',
                                        self.num_days_inactive_account if self.num_days_inactive_account else 'Indeterminado',
                                        'Correcto' if self.num_days_inactive_account and self.num_days_inactive_account > 30 else 'Incorrecto'])
        return self.num_days_inactive_account

    def _get_encryption_pass(self):
        self.encryption_pass = None
        config_file = get_config_from_file('/etc/pam.d/common-password', '#')
        if config_file and 'password' in config_file:
            password_config = config_file.get('password')
            encryption_types = ['sha256', 'sha512']
            for encryption_type in encryption_types:
                if encryption_type in password_config:
                    self.encryption_pass = encryption_type
                    break
        self.entries_to_display.append(['Cifrado seguro de la cuenta',
                                        self.encryption_pass.upper() if self.encryption_pass else 'Indeterminado',
                                        'Correcto' if self.encryption_pass else 'Incorrecto'])
        return self.encryption_pass

    def _get_counts_without_password(self):
        self.counts_without_password = False
        users_file = open('/etc/shadow', 'r')
        users_content = users_file.read().replace('\r', '').splitlines()
        for user in users_content:
            user_data = user.split(':')
            if user_data[1] == '':
                self.counts_without_password = True
                break
        self.entries_to_display.append(['Cuentas sin contraseña',
                                        'Sí' if self.counts_without_password else 'No',
                                        'Correcto' if self.counts_without_password else 'Incorrecto'])
        return self.counts_without_password

    def _check_FIPS(self):
        self.is_fips_enabled = False
        is_fips_installed = check_if_package_installed('linux-fips')
        if is_fips_installed:
            if os.path.exists('/proc/sys/crypto/fips_enabled'):
                file = open('/proc/sys/crypto/fips_enabled', 'r')
                content = file.read()
                if '1' in content:
                    self.is_fips_enabled = True
        self.entries_to_display.append(['Criptografía de sistema: usar algoritmos que cumplan FIPS para cifrado, firma y operaciones hash',
                                        'Sí' if self.is_fips_enabled else 'No', 'Correcto' if self.is_fips_enabled else 'Incorrecto'])
        return self.is_fips_enabled

    def get_params(self):
        self._get_pass_min_days()
        self._get_pass_max_days()
        self._get_pass_warn_age()
        self._get_num_days_inactive_account()
        self._get_min_length_pass()
        self._get_complexity_pass()
        self._get_encryption_pass()
        self._get_avoid_use_same_pass()
        self._get_counts_without_password()
        self._check_FIPS()


class LocalAccess(BaseModel):
    # OP.ACC.6 - Acceso Local
    title = 'OP.ACC.6 - Acceso local'
    entries_to_display = []

    def _get_account_lock_threshold(self):
        self.account_lock_threshold = -1
        config_file = get_config_from_file('/etc/pam.d/login', '#')
        if config_file:
            for line in config_file:
                if 'deny' in line:
                    config_params = line.replace('\r', '').split(' ', '')
                    for param in config_params:
                        if 'deny' in param:
                            self.account_lock_threshold = param.split('=')[1]
        self.entries_to_display.append(['Umbral de bloqueo de cuenta', self.account_lock_threshold if self.account_lock_threshold and self.account_lock_threshold > 8 else 'No', 'Correcto' if self.account_lock_threshold else 'Incorrecto'])
        return self.account_lock_threshold

    def _get_unlock_time(self):
        self.unlock_time = -1
        config_file = get_config_from_file('/etc/pam.d/login', '#')
        if config_file:
            for line in config_file:
                if 'unlock_time' in line:
                    config_params = line.replace('\r', '').split(' ', '')
                    for param in config_params:
                        if 'unlock_time' in param:
                            self.unlock_time = param.split('=')[1]
        self.entries_to_display.append(['Restablecer el bloqueo de cuenta después de ', self.unlock_time if self.unlock_time and self.unlock_time > 30 else 'Indeterminado', 'Correcto' if self.unlock_time else 'Incorrecto'])
        return self.unlock_time

    def _show_last_login_on_tty(self):
        # ONLY WORK FOR PAM
        self.show_last_login = False
        config_file = get_config_from_file('/etc/pam.d/login', '#', True)
        if config_file and 'session    optional   pam_lastlog.so' in config_file:
            self.show_last_login = True
        self.entries_to_display.append(['Información del último logeo', 'Sí' if self.show_last_login else 'No', 'Correcto' if self.show_last_login else 'Incorrecto'])
        return self.show_last_login

    def get_params(self):
        self._get_account_lock_threshold()
        self._get_unlock_time()
        self._show_last_login_on_tty()


class RemoteAccess(BaseModel):
    # OP.ACC.7 - Acceso Remoto
    title = 'OP.ACC.7 - Acceso Remoto'
    entries_to_display = []

    def _get_host(self):
        # Check for not all ips
        self.host = False
        config_file = get_config_from_file('/etc/ssh/ssh_config', '#')
        if 'Host' in config_file and '*' not in config_file['Host']:
            self.host = True
        self.entries_to_display.append(['Acceso restringido a IPs', 'Sí' if self.host else 'No', 'Correcto' if self.host else 'Incorrecto'])
        return self.host

    def _get_public_key_authentication(self):
        # RSAAuthentication yes
        # PubKeyAuthentication yes
        self.public_key_authentication = False
        config_file = get_config_from_file('/etc/ssh/ssh_config', '#')
        if 'RSAAuthentication' in config_file and \
                'yes' in config_file['RSAAuthentication'] and \
                'PubKeyAuthentication' in config_file and \
                'yes' in config_file['PubKeyAuthentication']:
            self.public_key_authentication = True
        self.entries_to_display.append(['Autenticación mediante Clave Pública/Privada', 'Sí' if self.public_key_authentication else 'No', 'Correcto' if self.public_key_authentication else 'Incorrecto'])
        return self.public_key_authentication

    def _get_password_authentication(self):
        # ChallengeResponseAuthentication no
        # PasswordAuthentication no
        # UsePAM no
        self.password_authentication = False
        config_file = get_config_from_file('/etc/ssh/sshd_config', '#')
        if 'ChallengeResponseAuthentication' in config_file and \
                'yes' in config_file['ChallengeResponseAuthentication'] and \
                'PassWordAuthentication' in config_file and \
                'yes' in config_file['PassWordAuthentication'] and \
                'UsePAM' in config_file and \
                'yes' in config_file['UsePAM']:
            self.password_authentication = True
        self.entries_to_display.append(['Autenticación mediante contraseña', 'Sí' if self.password_authentication else 'No', 'Correcto' if self.password_authentication else 'Incorrecto'])
        return self.password_authentication

    def _get_protocol(self):
        # Default is 2,1
        # Good configuration is for only 2
        self.protocol = False
        config_file = get_config_from_file('/etc/ssh/sshd_config', '#')
        if 'Protocol' in config_file and config_file['Protocol'] == '2':
            self.protocol = True
        self.entries_to_display.append(['Versión de SSH usada', config_file['Protocol'] if 'Protocol' in config_file else '2,1', 'Correcto' if self.protocol else 'Incorrecto'])
        return self.protocol

    def _get_root_login(self):
        self.root_login = True
        config_file = get_config_from_file('/etc/ssh/sshd_config', '#')
        if 'PermitRootLogin' in config_file and config_file['PermitRootLogin'] == 'no':
            self.root_login = False
        self.entries_to_display.append(['Acceso con usuario Root', 'Sí' if self.root_login else 'No', 'Correcto' if self.root_login else 'Incorrecto'])
        return self.root_login

    def _show_last_login(self):
        self.last_login = True
        config_file = get_config_from_file('/etc/ssh/sshd_config', '#')
        if 'PrintlastLog' in config_file and config_file['PrintlastLog '] == 'no':
            self.last_login = False
        self.entries_to_display.append(['Información del último logeo', 'Sí' if self.last_login else 'No', 'Correcto' if self.last_login else 'Incorrecto'])
        return self.last_login

    def get_params(self):
        self._get_host()
        self._get_protocol()
        self._get_public_key_authentication()
        self._get_password_authentication()
        self._get_root_login()
        self._show_last_login()
