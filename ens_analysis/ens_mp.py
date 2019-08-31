# -*- coding: utf-8 -*-
from ens_analysis.ens_base import BaseModel
from utils.ens_utils import read_file, get_config_from_file, execute_command, check_if_package_installed, print_message


class WorkStationBlocking(BaseModel):
    # MP.EQ.2 - BLoqueo del puesto de trabajo
    title = 'MP.EQ.2 - Bloqueo del puesto de trabajo'
    entries_to_display = []

    def _check_autologout_shell(self):
        timeout = 0
        timeout_config_min = self.config_data.get('timeout_config_shell_min', 300)
        timeout_config_max = self.config_data.get('timeout_config_shell_max', 600)
        vars = {}
        content = read_file('/etc/profile.d/autologout.sh')
        lines = content.replace('\r', '').splitlines()
        for line in lines:
            line = line.strip()
            if '=' in line:
                line_splitted = line.split('=')
                vars[line_splitted[0]] = line_splitted[1]
            if 'readonly' in line:
                var_with_timeout = line.split()[1:].strip()
                if var_with_timeout in vars:
                    timeout = int(var_with_timeout)
                elif var_with_timeout.isdigit():
                    timeout = int(var_with_timeout)
        result = 'Incorrecto'
        if timeout:
            result = 'Correcto' if timeout >= timeout_config_min and timeout <= timeout_config_max else 'Incorrecto'
        description = 'El tiempo para el cierre de la sesión por inactividad para el terminal, debe de estar entre 300 y 600 segundos'
        self.entries_to_display.append(
            ['Tiempo para cierre de sesión debido a inactividad',
                timeout if timeout else 'Indeterminado', result, description])

    def _check_timeout_ssh(self):
        timeout = 0
        sshd_config = get_config_from_file('/etc/ssh/sshd_config', '#')
        timeout_config_min = self.config_data.get('timeout_config_shell_min', 300)
        timeout_config_max = self.config_data.get('timeout_config_shell_max', 600)
        if sshd_config and 'ClientAliveInterval' in sshd_config:
            timeout = sshd_config.get('ClientAliveInterval')
        result = 'Incorrecto'
        if timeout:
            result = 'Correcto' if timeout >= timeout_config_min and timeout <= timeout_config_max else 'Incorrecto'
        description = 'El tiempo para el cierre de la sesión por ssh debido a inactividad, debe de estar entre 300 y 600 segundos'
        self.entries_to_display.append(
            ['Tiempo para cierre de sesión debido a inactividad en SSH',
                timeout if timeout else 'Indeterminado', result, description])

        result = 'Incorrecto'
        client_alive_count_max = -1
        if 'ClientAliveCountMax' in sshd_config:
            client_alive_count_max = sshd_config['ClientAliveCountMax']
        result = 'Correcto' if client_alive_count_max == 0 else 'Incorrecto'
        description = """
            Número de mensajes que se envían a través de SSH para mantener activa la conexión.
            Debe de ser 0, para que el timeout de la conexión coincida correctamente"""
        self.entries_to_display.append(
            ['Número de mensajes Keep Alive antes de finalizar la sesión',
                'Indeterminado' if client_alive_count_max == -1 else client_alive_count_max,
                result, description])

    def get_params(self):
        print_message('ok', 'Analizando bloqueo de puesto de trabajo.')
        config = {
            0: [
                self._check_autologout_shell,
                self._check_timeout_ssh
            ],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de bloqueo de puesto de trabajo.')


class ProtectionComputerEquipment(BaseModel):
    # MP.EQ.3 - Protección de los equipos informáticos
    title = 'MP.EQ.3 - Protección de los equipos informáticos'
    entries_to_display = []

    def _check_crypt_partitions(self):
        partitions_crypted = None
        exists_partitions_crypted = secure_encryption = swap_crypted = False
        command = "ls /dev/mapper/ | grep crypt"
        content = execute_command(command)
        partitions_crypted = content.splitlines()
        for partition in partitions_crypted:
            if 'swap' in partition:
                swap_crypted = True
            exists_partitions_crypted = True
            check_status_command = 'cryptsetup status %s' % partition
            check_status_content = execute_command(check_status_command)
            result_status = check_status_content.splitlines()
            for info_config in result_status:
                cipher = size = ''
                info_config = info_config.strip()
                if info_config.startswith('cipher'):
                    cipher = info_config[7:]
                if info_config.startswith('keysize'):
                    size = info_config[8:]
                if 'aes-xts' in cipher and '512' in size:
                    secure_encryption = True
                else:
                    secure_encryption = False
        description = 'Deben de existir unidades cifradas en el sistema'
        self.entries_to_display.append([
            '¿Existen unidades cifradas?',
            'Sí' if exists_partitions_crypted else 'No',
            'Correcto' if exists_partitions_crypted else 'Incorrecto',
            description
        ])

        if exists_partitions_crypted:
            description = 'El método de cifrado de dichas unidades, debe de ser AES-XTS 512 bits'
            self.entries_to_display.append([
                'Método de cifrado de las unidades (AES-XTS 512 bits)',
                'Sí' if secure_encryption else 'No',
                'Correcto' if secure_encryption else 'Incorrecto',
                description
            ])

        description = 'La partición SWAP debe de estar cifrada'
        self.entries_to_display.append([
            '¿SWAP cifrado?',
            'Sí' if swap_crypted else 'No',
            'Correcto' if swap_crypted else 'Incorrecto',
            description
        ])

    def _check_partitions_splitted(self):
        partitions_splitted = True
        content = get_config_from_file("/etc/fstab", "#", return_full_content=True)
        mount_point_position = 1
        list_mount_point_separated = ['/', '/boot', '/usr', '/home', '/tmp', '/var', '/opt']
        list_mount_point_in_fstab = []
        for line in content:
            if line:
                line_splitted = line.split()
                list_mount_point_in_fstab.append(line_splitted[mount_point_position])
        for mount_point_to_check in list_mount_point_separated:
            if mount_point_to_check not in list_mount_point_in_fstab:
                partitions_splitted = False
                break
        result = 'Correcto' if partitions_splitted else 'Incorrecto'
        description = 'Los puntos de montaje siguientes: /, /boot, /usr, /home, /tmp, /var, /opt, deben de encontrarse en particiones separadas'
        self.entries_to_display.append(
            ['Puntos de montaje en diferentes particiones',
                'Sí' if partitions_splitted else 'No', result, description])

    def get_params(self):
        print_message('ok', 'Analizando protección de los equipos.')
        config = {
            0: [
                self._check_crypt_partitions,
                self._check_partitions_splitted
            ],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de protección de los equipos.')


class ProtectionAuthenticityIntegrity(BaseModel):
    # MP.COM.3 - Protección de la autenticidad y de la integridad
    title = 'MP.COM.3 - Protección de la autenticidad y de la integridad'
    entries_to_display = []

    def _check_unsecure_packages(self):
        list_packages = [
            'telnet', 'ftp', 'tftp', 'rlogin', 'rsh', 'nis', 'talk',
        ]

        for package in list_packages:
            package_installed = check_if_package_installed(package)
            result = 'Correcto' if not package_installed else 'Incorrecto'
            description = 'Por seguridad, el servicio {0}, debe de estar eliminado del sistema'.format(package)
            self.entries_to_display.append([
                'Paquete ' + package.upper() + ' instalado',
                'Sí' if package_installed else 'No',
                result, description
            ])

    def get_params(self):
        print_message('ok', 'Analizando protección de la autenticidad y la integridad.')
        config = {
            0: [
                self._check_unsecure_packages],
            1: [],
            2: [],
        }
        self.get_max_lvl(config)
        print_message('ok', 'Fin de protección de la autenticidad y la integridad.')
