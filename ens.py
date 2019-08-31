# -*- coding: utf-8 -*-
import os

import argparse
from datetime import datetime
from decimal import Decimal

from ens_analysis.ens_op_acc import *
from ens_analysis.ens_op_exp import *
from ens_analysis.ens_mp import *
from ens_analysis.ens_extra_data import ExtraConfigJson
from utils.ens_utils import check_if_linux_system, check_if_is_root, generate_pdf
from utils.ens_html_utils import full_html


def check_arguments(seguridad=None, configuracion_base=None, configuracion_externa=None):
    if seguridad and seguridad not in ['alto', 'medio', 'bajo']:
        print_message('error', 'El parámetro de seguridad, tiene que ser: alto, medio o bajo')
        exit()

    if not check_if_linux_system():
        print_message('error', 'El sistema debe de ser Linux')
        exit()

    if not check_if_is_root():
        print_message('error', 'Para ejecutar este software, debe de hacerlo con permisos de administrador')
        exit()

    if configuracion_base and not os.path.exists(configuracion_base):
        print_message('error', 'El fichero de configuración indicado no existe')
        exit()

    if configuracion_externa and not os.path.exists(configuracion_externa):
        print_message('error', 'El fichero de configuración adicional no existe')
        exit()


def ENS(nombre_usuario, nombre_organizacion, nombre_fichero=None, nivel_seguridad=None, configuracion_base=None, configuracion_externa=None, pdf=None):
    html = ""
    score = Decimal(0)
    initial_time = datetime.now()

    if not nombre_fichero:
        nombre_fichero = 'resultado_ens.html'

    list_classes_to_check = [
        AccessRightsManagement,
        AuthenticationMechanisms,
        LocalAccess,
        RemoteAccess,
        SecurityConfigurations,
        ChangeManagement,
        ProtectionAgainstHarmfulCode,
        RegisterActivityLogs,
        WorkStationBlocking,
        ProtectionComputerEquipment,
        ProtectionAuthenticityIntegrity,
    ]

    lvl_security_list = []
    for each_class in list_classes_to_check:
        instance = each_class(nivel=nivel_seguridad, configuracion_base=configuracion_base)
        lvl_security_list.append(instance.max_lvl_security)
        if isinstance(instance, RegisterActivityLogs):
            html += instance.get_html_exp8()
            score += Decimal(instance.get_results(instance.params_logs)[0])
            html += instance.get_html_exp10()
            score += Decimal(instance.get_results(instance.log_permissions_parsed)[0])
        else:
            score += Decimal(instance.get_results()[0])
            html += instance.get_html()

    if configuracion_externa:
        instance = ExtraConfigJson(configuracion_externa)
        html += instance.get_html()

    lvl_security = 'Bajo'
    if 'Alto' in lvl_security_list:
        lvl_security = 'Alto'
    elif 'Medio' in lvl_security_list:
        lvl_security = 'Medio'

    html_file = open(nombre_fichero, 'w')
    score_str = '{0:.2f}'.format(score / len(list_classes_to_check))

    html = full_html(html, score_str, nombre_usuario, nombre_organizacion, lvl_security)
    try:
        import bs4
        soup = bs4.BeautifulSoup(html, features="html5lib")
        html = soup.prettify()
    except ImportError:
        print_message('warning', 'BeautifulSoup no está instalado.\nEl html generado no está parseado. En caso de generar un documento PDF, es posible que el documento generado no contenga el HTML completo.')
    html_file.write(html)
    html_file.close()

    if pdf:
        generate_pdf(html)

    print_message('ok', 'Análisis del ENS finalizado. Consulte el documento generado.')
    total_time = datetime.now() - initial_time
    print('\nTiempo de ejecución: {0} segundos'.format(total_time.total_seconds()))


parser = argparse.ArgumentParser()

parser.add_argument('nombre_usuario', help='Indica el nombre del usuario que ha solicitado el informe')
parser.add_argument('nombre_organizacion', help='Indica el nombre de la organización a la cual se le está aplicando el informe')
parser.add_argument('-ns', '--nivel-seguridad', help='Indica el nivel de seguridad del ENS. Valores aceptados: alto, medio, bajo')
parser.add_argument('-c', '--configuracion', help='Especifica un fichero de configuración externo')
parser.add_argument('-ce', '--configuracion-externa', help='Especifica un fichero de configuración para otros servicios')
parser.add_argument('-f', '--nombre-fichero', help='Especifica el nombre del fichero html con el resultado')
parser.add_argument('-p', '--pdf', help='Indica si un documento PDF se generará a través del HMTL', action='store_true', default=False)

arguments = parser.parse_args()

check_arguments(
    seguridad=arguments.nivel_seguridad,
    configuracion_base=arguments.configuracion,
    configuracion_externa=arguments.configuracion_externa
)

ENS(
    nombre_usuario=arguments.nombre_usuario,
    nombre_organizacion=arguments.nombre_organizacion,
    nombre_fichero=arguments.nombre_fichero,
    nivel_seguridad=arguments.nivel_seguridad,
    configuracion_base=arguments.configuracion,
    configuracion_externa=arguments.configuracion_externa,
    pdf=arguments.pdf,
)
