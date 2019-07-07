import json


class BaseModel():

    def __init__(self):
        self.load_config_file()
        self.get_params()

    def get_params(self):
        pass

    def get_html(self):
        html = """
            <div class="panel-group" style='margin-bottom: 0px'>
                <div class="panel panel-default"><div class="panel-heading">
                    <h4 class="panel-title">
                        <a data-toggle="collapse" href='#""" + self.title.replace(' ', '').replace('-', '').replace('.', '') + """'>
                            <strong>""" + self.title + """</strong>
                        </a>
                    </h4>
                </div><div id=""" + self.title.replace(' ', '').replace('-', '').replace('.', '') + """ class="panel-collapse collapse">
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
        for entry in self.entries_to_display:
            color = 'red'
            if entry[2] == 'Correcto':
                color = 'green'
            html += "<tr><th style='padding-right: 10px; vertical-align: top;'>%s</th><th style='padding-right: 10px; vertical-align: top; color:%s'>%s</th><th style='text-align: center; vertical-align: top; color:%s'><strong>%s</strong></th></tr>" % (entry[0], color, entry[1], color, entry[2])
        html += """</tbody></table></div></div></div></div>"""
        return html

    def load_config_file(self):
        self.data = {}
        # with open('config.json') as json_file:
        #     self.data = json.load(json_file)
        return self.data
