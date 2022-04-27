# grafana_export_import
Export, Import grafana configuration with datasources and passwords for them (except users in groups).
Does not preserve IDs (UID are still exported/imported). creates new IDs in new grafana
Can export from Postgresql and import to Mysql/Mariadb and vice versa.

# using
for export:
python.exe .\main.py --api_key <> --export_srv <> --dir '<dir to export configuration>' --db_server <ip or hostname>:<port> --db_user <databse login> --db_password <> --db_name <> --db_type <M or P, M for mysql/mariadb, P for postgresql>

for import:
python.exe .\main.py --api_key <> --import_srv <> --dir <directory with exported files> --set_default_datasource '<default datasource name, which is null in dashboards>' --db_server <ip or hostname>:<port> --db_user <> --db_password <> --db_name <> --db_type <M or P, M for mysql/mariadb, P for postgresql>
