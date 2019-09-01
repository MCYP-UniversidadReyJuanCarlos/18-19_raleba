# -*- coding: utf-8 -*-

from datetime import datetime
from utils.ens_utils import execute_command, print_message
from ens_analysis.ens_extra_data import OpenPortsInformation, ServicesOnBoot


def full_html(html, score_str, nombre_usuario, nombre_organizacion, lvl_security):
    """Generate html with ens result

    Args:
        html (str): html from ens_analysis
        score_str (str): total score
        nombre_usuario: username
        nombre_organizacion: organization name's
        lvl_security: security level

    Returns:
        str: return html content
    """
    print_message('ok', 'Generando fichero HTML.')
    full_html = """
        <!DOCTYPE html>
        <html lang="es">
           <head>
              <meta charset="utf-8">
              <link rel="stylesheet" href="statics/css/bootstrap.min.css">
              <script src="statics/js/jquery.min.js"></script>
              <script src="statics/js/bootstrap.min.js"></script>
              <style>
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
                    padding-left: 16px;
                    font-weight: bold;
                    color: white !important;
                    font-family: TAHOMA;
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
                .red{
                    color: #FF0000 !important;
                }
                .green{
                    color: #008000 !important;
                }
              </style>
           </head>
           <body style="width: 98%; margin-left: 1%">
           <br>
    """
    full_html += get_header(nombre_organizacion, nombre_usuario, lvl_security)
    from ens_analysis import ens_extra_data as extra_config
    instance = extra_config.SystemInfo()
    info_system = instance.get_html()
    full_html += info_system
    full_html += """
                <br>
                <div class="well" style="width: 100%; padding: 0">
                    <div class="div_title_top" style="background-color: #4169E1;">
                        <span>
                            Resultado del ENS
                        </span>
                    </div>
                    <div style="width: 100%; padding-left: 1%;">
                        <div class="panel-group" style='margin-bottom: 0px'>
                            <div class="panel panel-default" style="padding-top: 20px; padding-bottom:20px;">
                               <div class="panel-collapse">
                                  <div class="panel-body">
                                     <table style="width: 100%">
                                        <tbody>
                                           <tr>
                                                <th style='padding-right: 10px; vertical-align: top; width: 30%; font-weight: bold;'>Porcentaje del ENS con éxito:</th>
                                                <th style='padding-right: 10px; vertical-align: top;'>""" + score_str + """%</th>
                                           </tr>
                                           <tr></tr><tr></tr><tr></tr>
                                           <tr style="margin-top: 5px;">
                                                <th style='padding-right: 10px; vertical-align: top; width: 30%; font-weight: bold;'>Nivel del ENS alcanzado:</th>
                                                <th style='padding-right: 10px; vertical-align: top;'>""" + lvl_security + """</th>
                                           </tr>
                                        </tbody>
                                     </table>
                                  </div>
                               </div>
                            </div>
                        </div>
                    </div>
    """
    full_html += html

    services_on_boot = ServicesOnBoot()
    open_ports = OpenPortsInformation()
    full_html += services_on_boot.get_html()
    full_html += open_ports.get_html()

    full_html += """
        </div></body></html>
    """
    print_message('ok', 'Fin de generación del documento HTML')
    return full_html


def get_header(company, user, security_lvl):
    """Generate html with ens result

    Args:
        company (str): company name
        user (str): username
        security_lvl: security level

    Returns:
        str: return html header
    """
    system_name = execute_command('hostname')
    html = """
        <div style="width: 100%; display: table;">
            <div style="font-size: 16px; width: 60%; border-bottom: 5px solid #4169E1; float:left;" >
                <span><strong>Nombre del sistema:</strong> {0}</span><br>
                <span><strong>Organización:</strong> {1}</span><br>
                <span><strong>Usuario Solicitante:</strong> {2}</span><br>
                <span><strong>Nivel de seguridad a comprobar:</strong> {3}</span><br>
                <span><strong>Fecha del informe:</strong> {4}</span><br><br>
            </div>
            <div style="width: 40%; float:left; text-align: center;">
                <img style="width: 80%; height: 120px;" src='statics/img/ens.jpg'></span>
            </div>
        </div>
        <br>
    """.format(system_name, company, user, security_lvl, datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
    return html
