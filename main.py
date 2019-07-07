from op_acc import *
from op_exp import *
from utils import check_if_linux_system, check_if_is_root, full_html

if __name__ == '__main__':

    if not check_if_linux_system():
        print ('Error de sistema:\nEl sistema debe de ser Linux')
        exit()

    if not check_if_is_root():
        print ('Permisos Insuficientes:\nPara ejecutar este software, debe de hacerlo con permisos de administrador')
        exit()

    html = ""
    list_classes_to_check = [
        AuthenticationMechanisms,
        LocalAccess,
        RemoteAccess,
        ChangeManagement,
        ProtectionAgainstHarmfulCode,
        RegisterActivityLogs,
    ]

    for each_class in list_classes_to_check:
        instance = each_class()
        if isinstance(instance, RegisterActivityLogs):
            html += instance.get_html_exp8()
            html += instance.get_html_exp10()
        else:
            html += instance.get_html()

    html_file = open('resultado_ens.html', 'w')
    html_file.write(full_html(html))
    html_file.close()
