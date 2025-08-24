from ipaddress import ip_network

mariaDB = (node.os == 'debian' and node.os_version[0] >= 9)

# TODO: make version aware
if node.os == 'debian' and node.os_version[0] >= 10:
    pkg_name = 'mariadb-server'
else:
    pkg_name = 'mysql-server'

svc_systemd = {
    "mysql": {
        'needs': [f'pkg_apt:{pkg_name}'],
    }
}

mysql_users = {}

mysql_dbs = {}
files = {}

# check if we need to listen on all interfaces
all_v4 = False
all_v6 = False

for username, user in node.metadata.get('mysql', {}).get('users', {}).items():
    if user.get('delete', False):
        mysql_users[username] = {
            'delete': True,
            'needs': [f'pkg_apt:{pkg_name}'],
        }
        continue

    auth_type = user.get('auth_type', 'mysql_native_password')

    if auth_type == 'unix_socket':
        hosts = user.get('allowed_hosts', ['localhost']).copy()
    else:
        hosts = user.get('allowed_hosts', ['127.0.0.1', '::1', 'localhost']).copy()

    mysql_users[username] = {
        'hosts': hosts,
        'db_priv': {},
        'needs': [f'pkg_apt:{pkg_name}'],
        'auth_type': auth_type,
    }

    if auth_type != 'unix_socket':
        pw_hash = user.get('password_hash', None)
        if pw_hash is not None:
            mysql_users[username]['password_hash'] = pw_hash
        else:
            mysql_users[username]['password'] = user.get('password', repo.vault.password_for("mysql_{}_mysql_user_{}".format(username, node.name)))

    for allowed_host in user.get('allowed_hosts', []):
        try:
            host = ip_network(allowed_host)

            if host.version == 4:
                all_v4 = True

            if host.version == 6:
                all_v6 = True
        except ValueError:
            pass

    for db, db_rights in user.get('db_priv', {}).items():
        mysql_users[username]['db_priv'][db] = db_rights
        mysql_dbs[db] = {}

if node.os == 'debian' and node.os_version[0] >= 12:
    default_collation = 'utf8mb3_general_ci'
    default_character_set = 'utf8mb3'
else:
    default_collation = 'utf8_general_ci'
    default_character_set = 'utf8'

for db, db_config in node.metadata.get('mysql', {}).get('dbs', {}).items():
    mysql_dbs[db] = {
        'collation': db_config.get('collation', default_collation),
        'character_set': db_config.get('character_set', default_character_set),
        'needs': [f'pkg_apt:{pkg_name}'],
    }

bind_address = '127.0.0.1'

if all_v4:
    bind_address = '0.0.0.0'

if all_v6:
    bind_address = '::'

if mariaDB:
    files['/etc/mysql/mariadb.conf.d/99-custom.cnf'] = {
        'content': '[mysqld]\n' +
                   f'bind-address = {bind_address}\n' +
                   'max_allowed_packet = {}\n'.format(node.metadata.get('mysql', {}).get('max_allowed_packet', '64M')) +
                   'max_connections = {}\n'.format(node.metadata.get('mysql', {}).get('max_connections', '500')),
        'content_type': 'text',
        'mode': "0644",
        'owner': "root",
        'group': "root",
        'triggers': ["svc_systemd:mysql:restart"],
    }
else:
    files['/etc/mysql/conf.d/99-custom.cnf'] = {
        'content': '[mysqld]\n'
                   'bind-address = {}\n'.format(bind_address),
        'content_type': 'text',
        'mode': "0644",
        'owner': "root",
        'group': "root",
        'triggers': ["svc_systemd:mysql:restart"],
    }
