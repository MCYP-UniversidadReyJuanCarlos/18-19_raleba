import json

from functools import reduce

level_parser = {
    'alto': 3,
    'medio': 2,
    'bajo': 1,
}

system = 'ubuntu'


class BaseModel:

    def __init__(self, nivel=None, configuracion_base=None):
        self.max_lvl_security = ''
        if not nivel:
            nivel = 'alto'
        self.level_config = level_parser.get(nivel)
        self.load_config_file()
        self.get_params()

    def get_params(self):
        pass

    def get_max_lvl(self, config):
        configs_to_check = []
        for index in range(self.level_config):
            configs_to_check = config.get(index)
            for individual_config in configs_to_check:
                result = individual_config()
                if result == 'Correcto':
                    if index == 0:
                        self.max_lvl_security = 'Bajo'
                    elif index == 1:
                        self.max_lvl_security = 'Medio'
                    else:
                        self.max_lvl_security = 'Alto'

    def get_results(self, entries=None):
        if entries:
            entries_to_check = entries
        else:
            entries_to_check = self.entries_to_display
        total_configs_validated = 0
        total_configs = len(entries_to_check)
        if total_configs:
            for entry in entries_to_check:
                if entry[2] == 'Correcto':
                    total_configs_validated += 1
            percentage_validated = (float(total_configs_validated) / float(total_configs)) * 100
            percentage_validated = '{0:.2f}'.format(percentage_validated)
            return percentage_validated, total_configs, total_configs_validated
        else:
            return '---', total_configs, total_configs_validated

    def get_html(self, title=None, percentage=None, entries=None):
        replaces = (' ', ''), ('.', ''), ('-', '')
        if not title:
            title = self.title
        if not entries:
            entries = self.entries_to_display
        percentage_calculated, total_items, total_items_validated = self.get_results(entries)
        if percentage:
            percentage_calculated = percentage
        title_replaced = reduce(lambda a, kv: a.replace(*kv), replaces, title)
        html = """
            <div class="panel-group" style='margin-bottom: 0px'>
                <div class="panel panel-default"><div class="panel-heading">
                    <h4 class="panel-title">
                        <a class="title_a" data-toggle="collapse" href='#{0}'>
                            {1} - ( {3} de {4} validados - {2} % )
                        </a>
                    </h4>
                </div><div id='{0}' class="panel-collapse collapse">
            <div class="panel-body">
                <table style="width: 100%">
                    <thead>
                        <tr>
                            <th style="width: 40%; padding-right: 10px;">
                                Nombre
                            </th>
                            <th style="width: 40%; padding-right: 10px;">
                                Valor
                            </th>
                            <th style="width: 20%;">
                                Resultado
                            </th>
                        </tr>
                    </thead>
                    <tbody>
        """.format(title_replaced, title, percentage_calculated, total_items_validated, total_items)
        for entry in entries:
            color = '#FF0000'
            if entry[2] == 'Correcto':
                color = '#008000'
            html += """
                <tr><th style='padding-right: 10px; vertical-align: top; text-align: justify'>
                    <strong>{0}</strong>
                </th><th style='padding-right: 10px; vertical-align: top; color: {1} !important'>
                    {2}
                </th><th style='vertical-align: top; color: {1} !important'>
                    {3}
                </th></tr>
            """.format(entry[0], color, entry[1], entry[2])
            if len(entry) == 4 and entry[3]:
                html += """<tr><th style="font-style: oblique; padding-left: 3em; padding-right: 3em; text-align: justify;">    {0}<th></tr>""".format(entry[3])
        html += """</tbody></table></div></div></div></div>"""
        return html

    def load_config_file(self):
        self.config_data = {}
        with open('data/config.json') as json_file:
            self.config_data = json.load(json_file)
        return self.config_data
