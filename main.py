import sys
import requests
import os
import json
from config import Configuration
import pymysql.cursors # pip install PyMySQL
import psycopg2
import psycopg2.extras
import unicodedata
import re

def slugify(value, allow_unicode=False):
    """
    Taken from https://github.com/django/django/blob/master/django/utils/text.py
    Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
    dashes to single dashes. Remove characters that aren't alphanumerics,
    underscores, or hyphens. Convert to lowercase. Also strip leading and
    trailing whitespace, dashes, and underscores.
    """
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize('NFKC', value)
    else:
        value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
    value = re.sub(r'[^\w\s-]', '', value.lower())
    return re.sub(r'[-\s]+', '-', value).strip('-_')

def write_to_file(dir:str,filename:str,to_write:dict)->None:
    tmp = open(os.path.join(dir, filename), 'w')
    tmp.write(json.dumps(to_write,default=str))
    tmp.close()
"""
def export_from_postgresql(server_db:str,login_db:str,password_db:str,database:str) -> tuple:
    dashboards = {}
    datasources = {}
    [server,port] = server_db.split(':')
    # Connect to the database
    connection = psycopg2.connect(host=server,
                                  port=port,
                                  user=login_db,
                                  password=password_db,
                                  database=database)

    cursor = connection.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
    sql = f"SELECT data,uid FROM dashboard;"
    cursor.execute(sql)
    for line in cursor.fetchall():
        dashboards[line['uid']] = json.loads(line['data'])

    sql = f"SELECT * FROM data_source;"
    cursor.execute(sql)
    for line in cursor.fetchall():
        datasources[line['uid']] = line

    cursor.close()
    connection.close()

    return (dashboards,datasources)
"""
def export_from_db(server_db:str,login_db:str,password_db:str,database:str,db_type:str) -> tuple:
    dashboards = {}
    datasources = {}
    [server,port] = server_db.split(':')
    connection = None
    cursor = None
    if db_type == 'M':
        # Connect to the database
        connection = pymysql.connect(host=server,
                                 port=int(port),
                                 user=login_db,
                                 password=password_db,
                                 database=database,
                                 cursorclass=pymysql.cursors.DictCursor)
        cursor = connection.cursor()
    elif db_type == 'P':
        connection = psycopg2.connect(host=server,
                                      port=port,
                                      user=login_db,
                                      password=password_db,
                                      database=database)
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        print(f'unsupported db_type {db_type}')
        sys.exit()
    #sql = f"SELECT `data`, `uid` FROM `{database}`.dashboard"
    sql = "SELECT data,uid FROM dashboard;"
    cursor.execute(sql)
    for line in cursor.fetchall():
        dashboards[line['uid']] = json.loads(line['data'])

    #sql = f"SELECT * FROM `{database}`.data_source"
    sql = "SELECT * FROM data_source;"
    cursor.execute(sql)
    for line in cursor.fetchall():
        datasources[line['uid']] = line

    cursor.close()
    connection.close()

    return (dashboards,datasources)

def import_datasources_to_db(server_db:str,login_db:str,password_db:str,database:str,
                 db_type:str,to_insert:dict)->None:
    [server, port] = server_db.split(':')
    connection = None
    cursor = None
    if db_type == 'M':
        # Connect to the database
        connection = pymysql.connect(host=server,
                                 port=int(port),
                                 user=login_db,
                                 password=password_db,
                                 database=database,
                                 cursorclass=pymysql.cursors.DictCursor)
        cursor = connection.cursor()
    elif db_type == 'P':
        connection = psycopg2.connect(host=server,
                                      port=port,
                                      user=login_db,
                                      password=password_db,
                                      database=database)
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        print(f'unsupported db_type {db_type}')
        sys.exit()

    inserts =[]
    if db_type == 'P':
        for uid in to_insert.keys():
            basic_auth_user = to_insert[uid]['basic_auth_user']
            basic_auth_password = to_insert[uid]['basic_auth_password']
            secure_json_data = to_insert[uid]['secure_json_data']
            inserts.append(f"UPDATE data_source SET basic_auth_user = '{basic_auth_user}', "
                           f"basic_auth_password = '{basic_auth_password}', "
                           f"secure_json_data = '{secure_json_data}' WHERE uid = '{uid}';")

    for insert in inserts:
        cursor.execute(insert)

    connection.commit()
    cursor.close()
    connection.close()

def export_from_grafana(config)->None:
    server = config['export_srv']
    api_key = config['api_key']
    dir = config['dir']

    headers = {f'Authorization': f'Bearer {api_key}'}

    output = {}

    #print(headers)
    r = requests.get(f'{server}/api/datasources', headers=headers, verify=False)
    if r.status_code == 200:
        output['datasources'] = r.json()
    else:
        output['datasources'] = []

    r = requests.get(f'{server}/api/folders', headers=headers, verify=False)
    print('folders', r.reason)
    output['folders'] = r.json()

    ##############
    # teams
    r = requests.get(f'{server}/api/teams/search?query=&', headers=headers, verify=False)
    output['teams'] = r.json()

    ##############
    # folder permissions
    output['folder_permissions'] = {}
    output['dashboards'] = []
    for folder in output['folders']:
        r = requests.get('%s/api/folders/%s/permissions' % (server, folder['uid']), headers=headers, verify=False)
        output['folder_permissions'][folder['uid']] = r.json()
        ##############
        # dashboards
        r = requests.get('%s/api/search?folderIds=%s&query=&' % (server, folder['id']), headers=headers, verify=False)
        dashboards = r.json()
        for d in dashboards:
            if d['type'] == 'dash-folder':
                continue
            # print(d)
            r = requests.get('%s/api/dashboards/uid/%s' % (server, d['uid']), headers=headers, verify=False)
            # print(r.json())
            data = r.json()['dashboard']
            data['folderUid'] = folder['uid']
            data['folderTitle'] = folder['title']
            output['dashboards'].append(data)

    if config['db_server'] != '-1' \
            and config['db_user'] != '-1' \
            and config['db_password'] != '-1' \
            and config['db_name'] != '-1' \
            and config['db_type'] != '-1':
        (dashboards, datasources) = export_from_db(config['db_server'],
                                                    config['db_user'],
                                                    config['db_password'],
                                                    config['db_name'],
                                                   config['db_type'])
        for i in range(len(output['dashboards'])):
            uid = output['dashboards'][i]['uid']
            if uid in dashboards.keys():
                output['dashboards'][i] = {**output['dashboards'][i],**dashboards[uid]}
            else:
                print(f'dashboard with {uid} and name ' + output['dashboards'][i]['title'] + ' doesn\'t found in database' )
        output['datasource_from_db'] = datasources
        #for i in range(len(output['datasources'])):
        #    uid = output['datasources'][i]['uid']
        #    if uid in datasources.keys():
        #        output['datasources'][i] = {**output['datasources'][i], **datasources[uid]}
        #    else:
        #        print(f'data source with {uid} and name ' + output['datasources'][i]['name'] + ' doesn\'t found in database')

    for setting in output:
        write_to_file(dir, f'{setting}.json', output[setting])

    if config['dashboards_as_files'] == 'True':
        default_datasource = ''
        if 'datasources' in output.keys():
            for temp in output['datasources']:
                if temp['isDefault']:
                    default_datasource = temp['name']
        for dashboard in output['dashboards']:
            ####
            # replace default data source by name
            if 'panels' in dashboard.keys() and default_datasource != '':
                for panel in dashboard['panels']:
                    if 'panels' in dashboard.keys():
                        for panel in dashboard['panels']:
                            if panel['datasource'] == None:
                                panel['datasource'] = default_datasource
            if 'templating' in dashboard.keys() and default_datasource != '':
                for variable in dashboard['templating']['list']:
                    if 'datasource' in variable.keys() and variable['datasource'] == None:
                        variable['datasource'] = default_datasource
            if 'folderTitle' in dashboard.keys() and 'title' in dashboard.keys():
                write_to_file(dir, slugify(dashboard['folderTitle']) + "_" + slugify(dashboard['title']) + '.json', dashboard)

def import_to_grafana(config)->None:
    server = config['import_srv']
    dir = config['dir']
    to_input = {}

    for setting in ['dashboards', 'datasources', 'datasource_from_db', 'folder_permissions',
                    'folders', 'teams']:
        f = open(dir + setting + '.json')
        to_input[setting] = json.load(f)
        f.close()

    #####
    # get default data source
    default_datasource = None
    for temp in to_input['datasources']:
        if temp['isDefault']:
            default_datasource = temp['name']
    if config['set_default_datasource'] != '-1':
        default_datasource = config['set_default_datasource']

    headers = {}
    api_key = config['api_key']
    headers = {f'Authorization': f'Bearer {api_key}'}

    #if config['update_dashboards_only'] != '-1' and config['update_dashboards_only']== 'True':
    #    for dashboard in to_input['dashboards']:
    #        if 'panels' in dashboard.keys():
    #            for panel in dashboard['panels']:
    #                if panel['datasource'] == None:
    #                    panel['datasource'] = default_datasource
    #        if 'templating' in dashboard.keys():
    #            for variable in dashboard['templating']['list']:
    #                if 'datasource' in variable.keys() and variable['datasource'] == None:
    #                    variable['datasource'] = default_datasource
    #        r = requests.post(f'{server}/api/dashboards/db', headers=headers,
    #                          json={'dashboard': dashboard, 'overwrite': True},
    #                          verify=False)
    #        print( dashboard['title'], r.json())
    #    return None

    ####
    # import datasources
    print('import data sources')
    for datasource in to_input['datasources']:
        del datasource['id']
        r = requests.post(f'{server}/api/datasources', headers=headers, json=datasource, verify=False)
        print(r.json())

    if len(to_input['datasource_from_db'].keys()) > 0:
        print('add datasource secrets directly to database')
        import_datasources_to_db(config['db_server'],
                            config['db_user'],
                            config['db_password'],
                            config['db_name'],
                            config['db_type'],
                             to_input['datasource_from_db'])

    """
    print('first get current data sources')
    current_datasources = {}
    r = requests.get(f'{server}/api/datasources', headers=headers, verify=False)
    for temp in r.json():
        current_datasources[temp['uid']]=temp
    for datasource in to_input['datasources']:
        del datasource['id']
        del datasource['created']
        del datasource['updated']
        datasource['secureJsonData'] = json.loads(datasource['secure_json_data'])
        del datasource['secure_json_data']
        if datasource['uid'] in current_datasources.keys():
            id = current_datasources[datasource['uid']]['id']
            #del datasource['uid']
            #print(datasource)
            r = requests.put(f'{server}/api/datasources/{id}', headers=headers, json=datasource, verify=False)
            print('updated ',r.json())
        else:
            r = requests.post(f'{server}/api/datasources', headers=headers, json=datasource, verify=False)
            print('created ',r.json())
    """
    ####
    # import folders
    print('import folders')
    for folder in to_input['folders']:
        del folder['id']
        r = requests.post(f'{server}/api/folders', headers=headers, json=folder, verify=False)
        print(folder['title'], r.json())

    ####
    # import teams
    print('import teams')
    for team in to_input['teams']:
        del team['id']
        r = requests.post(f'{server}/api/teams', headers=headers, json=team, verify=False)
        print(r.json())

    ####
    # get current folders
    r = requests.get(f'{server}/api/folders', headers=headers, verify=False)
    current_folders = {}
    for temp in r.json():
        current_folders[temp['title'].upper()] = temp
    print(current_folders)

    ####
    # import dashboards
    print('import dashboards')
    for dashboard in to_input['dashboards']:
        folderTitle = ""
        if 'folderTitle' in dashboard.keys():
            folderTitle = dashboard['folderTitle'].upper()
        else:
            for input_folder in to_input['folders']:
                if input_folder['uid'] == dashboard['folderUid']:
                    folderTitle = input_folder['title'].upper()
                    break
        del dashboard['id']
        if folderTitle == "":
            print('###################\n not find folder for dashboard with folder uid',
                  dashboard['folderUid'], dashboard['title'] )
            continue
        try:
            folderUid = current_folders[folderTitle]['uid']
        except Exception as e:
            print("###################\n ERROR ", e, dashboard['title'], "\n###################")
            continue
        del dashboard['folderUid']
        if 'folderTitle' in dashboard.keys():
            del dashboard['folderTitle']
        ####
        # replace default data source by name
        if 'panels' in dashboard.keys():
            for panel in dashboard['panels']:
                if 'panels' in dashboard.keys():
                    for panel in dashboard['panels']:
                        if panel['datasource'] == None:
                            panel['datasource'] = default_datasource
        if 'templating' in dashboard.keys():
            for variable in dashboard['templating']['list']:
                if 'datasource' in variable.keys() and variable['datasource'] == None:
                    variable['datasource'] = default_datasource
        r = requests.post(f'{server}/api/dashboards/db', headers=headers,
                          json={'dashboard':dashboard,'folderUid':folderUid,'overwrite':True},
                          verify=False)
        print(folderUid, dashboard['title'], r.json())

    ####
    # set permissions to folders
    print('first get ids of teams')
    r = requests.get(f'{server}/api/teams/search?query=&', headers=headers, verify=False)
    teams_new = {}
    for team in  r.json()['teams']:
        teams_new[team['name']] = team['id']

    print('set permissions to folders')
    permissions = {}
    for folderUid in to_input['folder_permissions'].keys():
        temp = to_input['folder_permissions'][folderUid]
        #permissions[folderUid] = []
        cur_folder_uid = ""
        for perm in temp:
            if perm['teamId'] != 0:
                new_team_id = teams_new[perm['team']]
                cur_folder_uid = current_folders[perm['title'].upper()]['uid']
                if cur_folder_uid not in permissions.keys():
                    permissions[cur_folder_uid] = []
                permissions[cur_folder_uid].append({'teamId': new_team_id, 'permission': perm['permission']})
            #if 'usrId' in perm.keys() and perm['usrId'] != 0:
            #    permissions[folderUid].append({'team': perm['userLogin'], 'permission': perm['permission']})
        if cur_folder_uid != '' and cur_folder_uid in permissions.keys() and len(permissions[cur_folder_uid]) != 0:
            r = requests.post('%s/api/folders/%s/permissions' % (server, cur_folder_uid), headers=headers, json={'items':permissions[cur_folder_uid]}, verify=False)
            print(r.json())

def main():
    configuration = Configuration()
    config = configuration.cmd_arguments()
    if config['export_srv'] != '-1' and config['import_srv'] != '-1':
        print('Both export_srv and import_srv are defined. Exit.')
        sys.exit()
    if config['export_srv'] != '-1':
        export_from_grafana(config)
    elif config['import_srv'] != '-1':
        import_to_grafana(config)

if __name__ == '__main__':
    main()
