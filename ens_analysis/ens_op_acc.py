# -*- coding: utf-8 -*-
import os

from ens_analysis.ens_base import BaseModel
from utils.ens_utils import get_config_from_file, get_pam_config, execute_command, check_if_package_installed, print_message


class AccessRightsManagement(BaseModel):
    # OP.ACC.4 Proceso de gestión de derechos de acceso
    title = 'OP.ACC.4 - Proceso de gestión de derechos de acceso'
    entries_to_display = []

    def _load_sudoers_config(self):
        self.sudoers_config = get_config_from_file('/etc/sudoers', '#', return_full_content=True)

    def _check_user_can_sudo_without_password(self):
        sudo_without_password = False
        for line in self.sudoers_config:
            if 'NOPASSWD' in line:
                sudo_without_password = True
                break
        result = 'Correcto' if not sudo_without_password else 'Incorrecto'
        description = 'No incluir la política "NOPASSWD" para preguntar la contraseña al usar sudo'
        self.entries_to_display.append(
            ['Usar sudo sin contraseña',
                'Sí' if sudo_without_password else 'No',
                result, description])
        return result

    def _check_always_ask_password(self):
        always_ask_password = False
        for line in self.sudoers_config:
            if 'timestamp_timeout=0' in line:
                always_ask_password = True
                break
        result = 'Correcto' if always_ask_password else 'Incorrecto'
        description = 'Usar la política "timestamp_timeout" a 0, hará que siempre se pregunte la contraseña al usar sudo'
        self.entries_to_display.append(
            ['Requerir contraseña de sudo siempre',
                'Sí' if always_ask_password else 'No',
                result, description])
        return result

    def get_params(self):
        print_message('ok', 'Analizando los procesos de gestión de derechos de acceso.')
        config = {
            0: [self._load_sudoers_config, self._check_user_can_sudo_without_password, self._check_always_ask_password],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de los procesos de gestión de derechos de acceso.')


class AuthenticationMechanisms(BaseModel):
    # OP.ACC.5 Mecanismos de autenticación
    title = 'OP.ACC.5 - Mecanismos de Autenticación'
    entries_to_display = []

    def _load_system_config_file(self):
        self.config_file = get_config_from_file('/etc/login.defs', '#')
        self.pam_commom_password_config = get_pam_config('/etc/pam.d/common-password', '#')

    def _get_pass_min_days(self):
        # Días como mínimo para cambiar la contraseña
        pass_min_days = None
        min_value = self.config_data['authentication'].get('min_days_password', 2)
        if self.config_file and 'PASS_MIN_DAYS' in self.config_file:
            pass_min_days = self.config_file.get('PASS_MIN_DAYS')
        result = 'Correcto' if pass_min_days and int(pass_min_days) >= min_value else 'Incorrecto'
        description = 'Número mínimo de días para cambiar la contraseña. El valor mínimo recomendado es 2'
        self.entries_to_display.append(['Vigencia mínima de la contraseña',
                                        pass_min_days if pass_min_days else 'Indeterminado',
                                        result, description])

    def _get_pass_max_days(self):
        # Días como máximo para cambiar la contraseña
        pass_max_days = 0
        max_value = self.config_data['authentication'].get('max_days_change_password', 45)
        if self.config_file and 'PASS_MAX_DAYS' in self.config_file:
            pass_max_days = self.config_file.get('PASS_MAX_DAYS')
        result = 'Correcto' if pass_max_days and int(pass_max_days) <= max_value else 'Incorrecto'
        description = 'Número máximo de días de la validez de la contraseña. El valor recomendado debe de ser igual o inferior a 45'
        self.entries_to_display.append(['Vigencia máxima de la contraseña',
                                        pass_max_days if pass_max_days else 'Indeterminado',
                                        result, description])

    def _get_pass_warn_age(self):
        # Días para el aviso de fin de vigencia de contraseña
        pass_warn_days = 0
        warn_days = self.config_data['authentication'].get('warn_days_password', 7)
        if self.config_file and 'PASS_WARN_AGE' in self.config_file:
            pass_warn_days = self.config_file.get('PASS_WARN_AGE')
        result = 'Correcto' if pass_warn_days and int(pass_warn_days) >= warn_days else 'Incorrecto'
        description = 'Número de días como mínimo para el aviso de fin de vigencia de la contraseña. El valor debe de ser igual o superior a 7'
        self.entries_to_display.append(['Aviso de fin de vigencia de la contraseña',
                                        pass_warn_days if pass_warn_days else 'Indeterminado',
                                        result, description])

    def _get_num_days_inactive_account(self):
        # Número de días para bloqueo de cuentas inactivas
        num_days_inactive_account = 0
        num_days_inactive_account_min = self.config_data['authentication'].get('num_days_inactive_min', 30)
        num_days_inactive_account_max = self.config_data['authentication'].get('num_days_inactive_max', 90)
        if self.pam_commom_password_config and 'password' in self.pam_commom_password_config:
            password_config = self.pam_commom_password_config.get('password')
            for config in password_config:
                params = config.split()
                for param in params:
                    if 'inactive' in param:
                        num_days_inactive_account = param.split('=')[1]
                        break
                if num_days_inactive_account:
                    break
        result = 'Correcto' if num_days_inactive_account and int(num_days_inactive_account) >= num_days_inactive_account_min and int(num_days_inactive_account) <= num_days_inactive_account_max else 'Incorrecto'
        description = 'Número de días para desactivar la cuenta por inactividad. El valor debe de estar entre 30 y 90'
        self.entries_to_display.append(
            ['Inactividad de cuenta (Número de días sin actividad para desactivar la cuenta)',
                num_days_inactive_account if num_days_inactive_account else 'Indeterminado',
                result, description])

    def _get_complexity_pass(self):
        # Complejidad de la contraseña
        complexity_pass = False
        if self.pam_commom_password_config and 'password' in self.pam_commom_password_config:
            password_config = self.pam_commom_password_config.get('password')
            for config in password_config:
                if ('ucredit=-1' in config and 'lcredit=-2' in config) and ('dcredit=-1' in config and 'ocredit=-1' in config):
                    complexity_pass = True
                    break
        result = 'Correcto' if complexity_pass else 'Incorrecto'
        description = 'La complejidad de la contraseña debe de ser: Al menos una letra mayúscula, 2 letras minúsculas, 1 dígito necesario y 1 carácter especial'
        self.entries_to_display.append(
            ['Complejidad de la contraseña',
                'Hay definida una política de complejidad adecuada' if complexity_pass else 'No hay definida una política de seguridad adecuada',
                result, description])

    def _get_min_length_pass(self):
        # Tamaño mínimo de la contraseña
        min_length_pass = 0
        min_length_pass_to_check = self.config_data['authentication'].get('min_length_password', 12)
        if self.pam_commom_password_config and 'password' in self.pam_commom_password_config:
            password_config = self.pam_commom_password_config.get('password')
            for config in password_config:
                params = config.split()
                for param in params:
                    if 'minlength' in param:
                        min_length_pass = param.split('=')[1]
                        break
                if min_length_pass:
                    break
        result = 'Correcto' if min_length_pass and int(min_length_pass) > min_length_pass_to_check else 'Incorrecto'
        description = 'La longitud de la contraseña ha de ser como mínimo de 12 carácteres'
        self.entries_to_display.append(
            ['Longitud mínima de la contraseña',
                min_length_pass if min_length_pass else 'Longitud mínima no determinada',
                result, description])

    def _get_avoid_use_same_pass(self):
        # Número de contraseñas mínimas para repetir contraseña
        avoid_use_same_pass = 0
        num_passwords_to_avoid_use_same_pass = self.config_data['authentication'].get('num_days_avoid_use_same_password', 7)
        if self.pam_commom_password_config and 'password' in self.pam_commom_password_config:
            password_config = self.pam_commom_password_config.get('password')
            for config in password_config:
                params = config.split()
                for param in params:
                    if 'remember' in param:
                        self.min_length_pass = param.split('=')[1]
                        break
                if avoid_use_same_pass:
                    break
        result = 'Correcto' if avoid_use_same_pass and avoid_use_same_pass >= num_passwords_to_avoid_use_same_pass else 'Incorrecto'
        description = 'El número de contraseñas anteriores para repetir la misma, tiene que ser de al menos 7'
        self.entries_to_display.append(
            ['Historial de contraseña (Número de contraseñas anteriores para repetir la misma contraseña)',
                avoid_use_same_pass if avoid_use_same_pass else 'Indeterminado',
                result, description])

    def _get_encryption_pass(self):
        # Cifrado de la contraseña
        encryption_pass = ''
        if self.pam_commom_password_config and 'password' in self.pam_commom_password_config:
            password_config = self.pam_commom_password_config.get('password')
            for config in password_config:
                if 'sha256' in config or 'sha512' in config:
                    encryption_pass = 'sha256' if 'sha256' in config else 'sha512'
                    break
        result = 'Correcto' if encryption_pass else 'Incorrecto'
        description = 'El cifrado de la contraseña debe de ser SHA256 o SHA512'
        self.entries_to_display.append(
            ['Cifrado de la contraseña',
                encryption_pass.upper() if encryption_pass else 'Indeterminado',
                result, description])

    def _get_counts_without_password(self):
        # Cuentas sin contraseña
        counts_without_password = False
        command = """awk -F: '($2 == "") {print}' /etc/shadow"""
        command_result = execute_command(command)
        if command_result:
            counts_without_password = True
        result = 'Correcto' if not counts_without_password else 'Incorrecto'
        description = 'No debe de existir ninguna cuenta en el sistema sin contraseña'
        self.entries_to_display.append(
            ['Cuentas sin contraseña',
                'Sí' if counts_without_password else 'No',
                result, description])

    def _check_FIPS(self):
        # Uso de FIPS
        is_fips_enabled = False
        is_fips_installed = check_if_package_installed('linux-fips')
        if is_fips_installed:
            if os.path.exists('/proc/sys/crypto/fips_enabled'):
                file = open('/proc/sys/crypto/fips_enabled', 'r')
                content = file.read()
                if '1' in content:
                    is_fips_enabled = True
        result = 'Correcto' if is_fips_enabled else 'Incorrecto'
        self.entries_to_display.append(
            ['Criptografía de sistema: usar algoritmos que cumplan FIPS para cifrado, firma y operaciones hash',
                'Sí' if is_fips_enabled else 'No', result])

    def get_params(self):
        print_message('ok', 'Analizando los mecanismos de autenticación.')
        config = {
            0: [
                self._load_system_config_file,
                self._get_pass_min_days,
                self._get_pass_max_days,
                self._get_min_length_pass,
                self._get_avoid_use_same_pass,
                self._get_pass_warn_age,
                self._get_complexity_pass,
                self._get_encryption_pass,
                self._get_num_days_inactive_account,
                self._get_counts_without_password,
            ],
            1: [
                self._check_FIPS,
            ],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de los mecanismos de autenticación.')


class LocalAccess(BaseModel):
    # OP.ACC.6 - Acceso Local
    title = 'OP.ACC.6 - Acceso local'
    entries_to_display = []

    def _load_system_config_file(self):
        self.pam_login_config = get_pam_config('/etc/pam.d/login', '#')

    def _get_account_lock_threshold(self):
        # Número de intentos erróneos hasta bloqueo
        account_lock_threshold = 0
        num_account_lock_threshold_min = self.config_data['local_access'].get(
            'account_lock_threshold_min', 5)
        num_account_lock_threshold_max = self.config_data['local_access'].get(
            'account_lock_threshold_max', 8)
        if self.pam_login_config and 'auth' in self.pam_login_config:
            config_file = self.pam_login_config.get('auth')
            for line in config_file:
                if 'deny' in line:
                    config_params = line.replace('\r', '').split()
                    for param in config_params:
                        if 'deny' in param:
                            account_lock_threshold = param.split('=')[1]
                            break
                    if account_lock_threshold:
                        break
        result = 'Correcto' if account_lock_threshold and int(account_lock_threshold) >= num_account_lock_threshold_min and int(account_lock_threshold) <= num_account_lock_threshold_max else 'Incorrecto'
        description = 'El número de accesos erróneos hasta bloqueo de la cuenta debe de estar entre 5 y 8'
        self.entries_to_display.append(
            ['Umbral de bloqueo de cuenta',
                account_lock_threshold if account_lock_threshold else 'Indeterminado',
                result, description])

    def _get_unlock_time(self):
        # Restablecer el bloqueo de cuenta despues de x seg
        unlock_time = 0
        min_unlock_time = self.config_data['local_access'].get('unlock_time', 1800)
        if self.pam_login_config and 'auth' in self.pam_login_config:
            config_file = self.pam_login_config.get('auth')
            for line in config_file:
                if 'unlock_time' in line:
                    config_params = line.replace('\r', '').split()
                    for param in config_params:
                        if 'unlock_time' in param:
                            unlock_time = param.split('=')[1]
                            break
                    if unlock_time:
                        break
        result = 'Correcto' if unlock_time and unlock_time > min_unlock_time else 'Incorrecto'
        description = 'Tiempo que la cuenta estará bloqueada. Debe de ser superior a 1800 segundos (30 minutos)'
        self.entries_to_display.append(
            ['Restablecer el bloqueo de cuenta después de ',
                unlock_time if unlock_time else 'Indeterminado',
                result, description])

    def _get_lock_account_root(self):
        # Bloquear cuenta root después de intentos fallidos de login
        lock_account_root = False
        if self.pam_login_config and 'auth' in self.pam_login_config:
            config_file = self.pam_login_config.get('auth')
            for line in config_file:
                if 'even_deny_root' in line:
                    lock_account_root = True
        result = 'Correcto' if lock_account_root else 'Incorrecto'
        description = 'Bloquear la cuenta root si se produce los intentos fallidos de login'
        self.entries_to_display.append(
            ['Bloquear contraseña root despues de intentos fallidos de login',
                'Sí' if lock_account_root else 'No',
                result, description])

    def _check_accounts_with_uid_to_0(self):
        counts_with_uid_to_0 = False
        command = """awk -F: '($3 == "0") {print}' /etc/passwd"""
        command_result = execute_command(command).splitlines()
        if len(command_result) > 1:
            counts_with_uid_to_0 = True
        result = 'Correcto' if not counts_with_uid_to_0 else 'Incorrecto'
        description = 'Solo debe de haber una cuenta con UID a 0, es decir, que sea superusuario, además del root'
        self.entries_to_display.append(
            ['Usuarios de sistema con UID a 0',
                'Sí' if counts_with_uid_to_0 else 'No', result, description])

    def _show_last_login_on_tty(self):
        # Mostrar último logeo en terminal
        show_last_login = False
        if self.pam_login_config and 'session' in self.pam_login_config:
            config_file = self.pam_login_config.get('session')
            for config in config_file:
                if 'pam_lastlog.so' in config:
                    show_last_login = True
                    break
        result = 'Correcto' if show_last_login else 'Incorrecto'
        description = 'Al acceder al terminal, debe de mostrarse información del último logeo'
        self.entries_to_display.append(
            ['Información del último logeo',
                'Sí' if show_last_login else 'No',
                result, description])

    def get_params(self):
        print_message('ok', 'Analizando acceso local.')
        config = {
            0: [
                self._load_system_config_file,
                self._get_account_lock_threshold,
                self._get_lock_account_root,
                self._get_unlock_time,
                self._check_accounts_with_uid_to_0,
                self._show_last_login_on_tty,
            ],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de acceso local.')


class RemoteAccess(BaseModel):
    # OP.ACC.7 - Acceso Remoto
    title = 'OP.ACC.7 - Acceso Remoto'
    entries_to_display = []

    def _load_system_config_file(self):
        self.config_file = get_config_from_file('/etc/ssh/sshd_config', '#')

    def _get_root_login(self):
        root_login = True
        if 'PermitRootLogin' in self.config_file and self.config_file['PermitRootLogin'] == 'no':
            root_login = False
        result = 'Correcto' if not root_login else 'Incorrecto'
        self.entries_to_display.append(
            ['Acceso con usuario Root', 'Sí' if root_login else 'No', result])

    def _get_host(self):
        # Check for not all ips
        host = False
        if 'Host' in self.config_file and '*' not in self.config_file['Host']:
            host = True
        result = 'Correcto' if host else 'Incorrecto'
        self.entries_to_display.append(
            ['Acceso restringido a IPs', 'Sí' if host else 'No', result])

    def _check_access_specific_users(self):
        usernames = False
        if 'AllowUsers' in self.config_file:
            usernames = True
        result = 'Correcto' if usernames else 'Incorrecto'
        self.entries_to_display.append(
            ['Acceso restringido a usuarios específicos', 'Sí' if usernames else 'No', result])

    def _get_protocol(self):
        # Default is 2,1
        # Good configuration is for only 2
        protocol = False
        protocol_values = self.config_data['remote_access'].get('protocol_for_ssh', "2")
        if 'Protocol' in self.config_file and self.config_file['Protocol'] == protocol_values:
            protocol = True
        result = 'Correcto' if protocol else 'Incorrecto'
        self.entries_to_display.append(
            ['Versión de SSH usada',
                protocol_values if protocol else '2,1',
                result])

    def _check_ignore_rhosts(self):
        ignore_rhost = False
        if 'IgnoreRhosts' in self.config_file and self.config_file['IgnoreRhosts'] == 'yes':
            ignore_rhost = True
        result = 'Correcto' if ignore_rhost else 'Incorrecto'
        self.entries_to_display.append(
            ['Ignorar Rhosts', 'Sí' if ignore_rhost else 'No', result])

    def _check_host_based_authentication(self):
        hostbasedauthentication = True
        if 'HostbasedAuthentication' in self.config_file and self.config_file['HostbasedAuthentication'] == 'no':
            hostbasedauthentication = False
        result = 'Correcto' if not hostbasedauthentication else 'Incorrecto'
        self.entries_to_display.append(
            ['Autenticación basada en host', 'Sí' if hostbasedauthentication else 'No', result])

    def _check_permit_empty_password(self):
        permit_empty_password = True
        if 'PermitEmptyPasswords' in self.config_file and self.config_file['PermitEmptyPasswords'] == 'no':
            permit_empty_password = False
        result = 'Correcto' if not permit_empty_password else 'Incorrecto'
        self.entries_to_display.append(
            ['Permitir contraseñas vacías', 'Sí' if permit_empty_password else 'No', result])

    def _check_x11_forwarding(self):
        x11forwarding = True
        if 'X11Forwarding' in self.config_file and self.config_file['X11Forwarding'] == 'no':
            x11forwarding = False
        result = 'Correcto' if not x11forwarding else 'Incorrecto'
        self.entries_to_display.append(
            ['Permitir X11Forwarding', 'Sí' if x11forwarding else 'No', result])

    def _check_max_auth_retries(self):
        max_auth_retries = 0
        if 'MaxAuthTries' in self.config_file:
            max_auth_retries = self.config_file['MaxAuthTries']
        result = 'Correcto' if max_auth_retries == '5' else 'Incorrecto'
        self.entries_to_display.append(
            ['Número máximo de reintentos', max_auth_retries, result])

    def _check_use_pam(self):
        use_pam = False
        if 'UsePAM' in self.config_file and self.config_file['UsePAM'] == 'yes':
            use_pam = True
        result = 'Correcto' if use_pam else 'Incorrecto'
        self.entries_to_display.append(
            ['Uso de PAM', 'Sí' if use_pam else 'No', result])

    def _get_public_key_authentication(self):
        # RSAAuthentication yes
        # PubKeyAuthentication yes
        public_key_authentication = False
        if 'RSAAuthentication' in self.config_file and \
                'yes' in self.config_file['RSAAuthentication'] and \
                'PubKeyAuthentication' in self.config_file and \
                'yes' in self.config_file['PubKeyAuthentication']:
            public_key_authentication = True
        result = 'Correcto' if public_key_authentication else 'Incorrecto'
        self.entries_to_display.append(
            ['Autenticación mediante Clave Pública/Privada',
                'Sí' if public_key_authentication else 'No',
                result])

    def _show_last_login(self):
        last_login = True
        if 'PrintlastLog' in self.config_file and self.config_file['PrintlastLog '] == 'no':
            last_login = False
        result = 'Correcto' if last_login else 'Incorrecto'
        self.entries_to_display.append(
            ['Información del último logeo', 'Sí' if last_login else 'No', result])

    def get_params(self):
        print_message('ok', 'Analizando acceso remoto.')
        config = {
            0: [
                self._load_system_config_file,
                self._get_root_login,
                self._get_host,
                self._check_access_specific_users,
                self._get_protocol,
                self._check_ignore_rhosts,
                self._check_host_based_authentication,
                self._check_permit_empty_password,
                self._check_x11_forwarding,
                self._check_max_auth_retries,
                self._check_use_pam,
                self._get_public_key_authentication,
                self._show_last_login,
            ],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de acceso remoto.')
