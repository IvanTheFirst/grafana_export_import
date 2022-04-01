from argparse import ArgumentParser

class Configuration:
    def __init__(self):
        #self.dict_of_buffers = dict_of_buffers
        pass

    def cmd_arguments(self)->dict:
        parser = ArgumentParser()
        output = {}
        parser.add_argument("--export_srv", dest="export_srv",
                            help="export server", required=False, default='-1')
        parser.add_argument("--db_server", dest="db_server",
                            help="export db server", required=False, default='-1')
        parser.add_argument("--db_user", dest="db_user",
                            required=False, default='-1')
        parser.add_argument("--db_password", dest="db_password",
                            required=False, default='-1')
        parser.add_argument("--db_type", dest="db_type", help='M for mariadb/mysql, P postgresql',
                            required=False, default='-1')
        parser.add_argument("--db_name", dest="db_name",
                            required=False, default='-1')
        parser.add_argument("--import_srv", dest="import_srv",
                            help="import server", required=False, default='-1')
        parser.add_argument("--api_key", dest="api_key",
                            help="api key to grafana", required=False, default='-1')
        parser.add_argument("--dir", dest="dir", required=False, default='-1')
        args = parser.parse_args()
        for k in vars(args).keys():
            output[k] = vars(args)[k]
        return output