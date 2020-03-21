from ipaddress import ip_network

mariaDB = (node.os == 'debian' and node.os_version[0] >= 9)

# TODO: make version aware
if node.os == 'debian' and node.os_version[0] >= 10:
    svc_systemd = {
        "mysql": {
            'needs': ['pkg_apt:mariadb-server'],
        }
    }
else:
    svc_systemd = {
        "mysql": {
            'needs': ['pkg_apt:mysql-server'],
        }
    }

mysql_users = {
    'root': {
        'superuser': True,
        'password': repo.vault.password_for("mysql_root_user_{}".format(node.name)),
    },
}

mysql_dbs = {}
files = {}

# check if we need to listen on all interfaces
all_v4 = False
all_v6 = False

for username, user in node.metadata.get('mysql', {}).get('users', {}).items():
    mysql_users[username] = {
        'password': user.get(
            'password',
            repo.vault.password_for("mysql_{}_mysql_user_{}".format(username, node.name))
        ),
        'hosts': user.get('allowed_hosts', ['127.0.0.1', '::1', 'localhost']).copy(),
        'db_priv': {},
    }

    for allowed_host in user.get('allowed_hosts', []):
        host = ip_network(allowed_host)

        if host.version == 4:
            all_v4 = True

        if host.version == 6:
            all_v6 = True

    for db, db_rights in user.get('db_priv', []).items():
        mysql_users[username]['db_priv'][db] = db_rights
        mysql_dbs[db] = {}

for db, db_config in node.metadata.get('mysql', {}).get('dbs', {}).items():
    mysql_dbs[db] = {
        'collation': db_config.get('collation', 'utf8_general_ci'),
        'character_set': db_config.get('character_set', 'utf8'),
    }

bind_address = '127.0.0.1'

if all_v4:
    bind_address = '0.0.0.0'

if all_v6:
    bind_address = '::'

if mariaDB:
    files['/etc/mysql/mariadb.conf.d/99-custom.cnf'] = {
        'content': '[mysqld]\n'
                   'bind-address = {}\n'.format(bind_address),
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
