from bundlewrap.items import Item, ItemStatus
from bundlewrap.exceptions import BundleError, RemoteException
from passlib.apps import mysql_context
from bundlewrap.utils.text import force_text, mark_for_translation as _
import types

AVAILABLE_PRIVS = [
    'Select_priv',
    'Insert_priv',
    'Update_priv',
    'Delete_priv',
    'Create_priv',
    'Drop_priv',
    'Reload_priv',
    'Shutdown_priv',
    'Process_priv',
    'File_priv',
    'Grant_priv',
    'References_priv',
    'Index_priv',
    'Alter_priv',
    'Show_db_priv',
    'Super_priv',
    'Create_tmp_table_priv',
    'Lock_tables_priv',
    'Execute_priv',
    'Repl_slave_priv',
    'Repl_client_priv',
    'Create_view_priv',
    'Show_view_priv',
    'Create_routine_priv',
    'Alter_routine_priv',
    'Create_user_priv',
    'Event_priv',
    'Trigger_priv',
    'Create_tablespace_priv',
]

SQL_AVAILABLE_PRIVS = {
    'Select_priv': 'SELECT',
    'Insert_priv': 'INSERT',
    'Update_priv': 'UPDATE',
    'Delete_priv': 'DELETE',
    'Create_priv': 'CREATE',
    'Drop_priv': 'DROP',
    'Reload_priv': 'RELOAD',
    'Shutdown_priv': 'SHUTDOWN',
    'Process_priv': 'PROCESS',
    'File_priv': 'FILE',
    'Grant_priv': 'GRANT OPTION',
    'References_priv': 'REFERENCES',
    'Index_priv': 'INDEX',
    'Alter_priv': 'ALTER',
    'Show_db_priv': 'SHOW DATABASES',
    'Super_priv': 'SUPER',
    'Create_tmp_table_priv': 'CREATE TEMPORARY TABLES',
    'Lock_tables_priv': 'LOCK TABLES',
    'Execute_priv': 'EXECUTE',
    'Repl_slave_priv': 'REPLICATION SLAVE',
    'Repl_client_priv': 'REPLICATION CLIENT',
    'Create_view_priv': 'CREATE VIEW',
    'Show_view_priv': 'SHOW VIEW',
    'Create_routine_priv': 'CREATE ROUTINE',
    'Alter_routine_priv': 'ALTER ROUTINE',
    'Create_user_priv': 'CREATE USER',
    'Event_priv': 'EVENT',
    'Trigger_priv': 'TRIGGER',
    'Create_tablespace_priv': 'CREATE TABLESPACE',
}

AVAILABLE_DB_PRIVS = [
    'Select_priv',
    'Insert_priv',
    'Update_priv',
    'Delete_priv',
    'Create_priv',
    'Drop_priv',
    'Grant_priv',
    'References_priv',
    'Index_priv',
    'Alter_priv',
    'Create_tmp_table_priv',
    'Lock_tables_priv',
    'Create_view_priv',
    'Show_view_priv',
    'Create_routine_priv',
    'Alter_routine_priv',
    'Execute_priv',
    'Event_priv',
    'Trigger_priv',
]

SQL_AVAILABLE_DB_PRIVS = {
    'Select_priv': 'SELECT',
    'Insert_priv': 'INSERT',
    'Update_priv': 'UPDATE',
    'Delete_priv': 'DELETE',
    'Create_priv': 'CREATE',
    'Drop_priv': 'DROP',
    'Grant_priv': 'GRANT OPTION',
    'References_priv': 'REFERENCES',
    'Index_priv': 'INDEX',
    'Alter_priv': 'ALTER',
    'Create_tmp_table_priv': 'CREATE TEMPORARY TABLES',
    'Lock_tables_priv': 'LOCK TABLES',
    'Create_view_priv': 'CREATE VIEW',
    'Show_view_priv': 'SHOW VIEW',
    'Create_routine_priv': 'CREATE ROUTINE',
    'Alter_routine_priv': 'ALTER ROUTINE',
    'Execute_priv': 'EXECUTE',
    'Event_priv': 'EVENT',
    'Trigger_priv': 'TRIGGER',
}

MYSQL_SCRIPT = "mysql --defaults-extra-file=/etc/mysql/debian.cnf"


def run_sql(node, sql):
    try:
        return node.run("echo \"{sql};\" | {mysql}".format(sql=sql, mysql=MYSQL_SCRIPT))
    except RemoteException:
        return None


def flush_right(node):
    return run_sql(node, "FLUSH PRIVILEGES")


def delete_user(node, user):
    res = run_sql(node, f"SELECT host FROM mysql.user WHERE User='{user}'")
    if res is None:
        return None

    hosts = []
    for line in res.stdout.decode().split("\n")[1:]:
        if line == '':
            continue
        hosts += [line, ]

    for host in hosts:
        run_sql(node, f"DROP USER '{user}'@'{host}';")


def generate_insert_user_sql(user, host, password, privs, sql_available_privileges):
    sql = f"CREATE USER '{user}'@'{host}' IDENTIFIED BY PASSWORD '{password}';"
    sql += generate_grant_privileges_sql(user, host, privs, sql_available_privileges)

    return sql


def generate_update_user_sql(user, host, password, privs, sql_available_privileges):
    sql = f"ALTER USER '{user}'@'{host}' IDENTIFIED BY PASSWORD '{password}';"
    sql += generate_grant_privileges_sql(user, host, privs, sql_available_privileges)

    return sql


def generate_grant_privileges_sql(user, host, privs, sql_available_privileges):
    sql = ''
    for priv, value in privs.items():
        if priv not in sql_available_privileges:
            continue

        priv = sql_available_privileges[priv]

        if value == 'Y':
            sql += f"GRANT {priv} ON *.* TO '{user}'@'{host}';"
        else:
            sql += f"REVOKE {priv} ON *.* FROM '{user}'@'{host}';"

    return sql


def generate_delete_user_sql(user, host):
    sql = f"DROP USER '{user}'@'{host}';"

    return sql


def generate_insert_db_priv_sql(user, db, host, privs, sql_available_db_privs):
    sql = ''
    for priv in [x for x, y in privs.items() if y == 'Y']:
        if priv not in sql_available_db_privs:
            continue

        priv = sql_available_db_privs[priv]
        sql += f"GRANT {priv} ON \`{db}\`.* TO '{user}'@'{host}'; "

    return sql


def generate_update_db_priv_sql(user, db, host, privs, sql_available_db_privs):
    sql = ''
    for priv, value in privs.items():
        if priv not in sql_available_db_privs:
            continue

        priv = sql_available_db_privs[priv]

        if value == 'Y':
            sql += f"GRANT {priv} ON \`{db}\`.* TO '{user}'@'{host}';"
        else:
            sql += f"REVOKE {priv} ON \`{db}\`.* FROM '{user}'@'{host}';"

    return sql


def generate_delete_db_priv_sql(user, db, host):
    sql = f"REVOKE ALL PRIVILEGES ON \`{db}\`.* FROM '{user}'@'{host}';"

    return sql


def fix_user(node, user, attrs, available_privs, sql_available_privs, create=False):
    password = attrs['password_hash']

    priv = {}
    for cur_priv in available_privs:
        priv[cur_priv] = "Y" if cur_priv in attrs['privileges'] else 'N'

    if create:
        for host in attrs['hosts']:
            sql = generate_insert_user_sql(user, host, password, priv, sql_available_privs)

            run_sql(node, sql)
    else:
        cur_hosts = get_user(node, user, available_privs)['hosts']
        hosts = attrs['hosts']

        # find missing; and deleted
        deleted = [val for val in cur_hosts if val not in hosts]
        added = [val for val in hosts if val not in cur_hosts]

        for host in deleted:
            run_sql(node, generate_delete_user_sql(user=user, host=host))

        for host in added:
            run_sql(node, generate_insert_user_sql(user, host, password, priv, sql_available_privs))

        for host in hosts:
            run_sql(node, generate_update_user_sql(user, host, password, priv, sql_available_privs))


def fix_db_priv(node, user, attrs, available_db_privs, sql_available_db_privs, create=False):
    if create:
        for db in attrs['db_priv']:
            priv = {}
            for cur_priv in available_db_privs:
                priv[cur_priv] = "Y" if cur_priv in attrs['db_priv'][db] else 'N'

            # create new privileges for this db for all hosts
            for host in attrs['hosts']:
                sql = generate_insert_db_priv_sql(user, db, host, priv, sql_available_db_privs)
                run_sql(node, sql)
    else:
        cur_privileges = get_user_privileges_for_dbs(node, user, available_db_privs)

        for db in attrs['db_priv']:
            priv = {}
            for cur_priv in available_db_privs:
                priv[cur_priv] = "Y" if cur_priv in attrs['db_priv'][db] else 'N'

            cur_hosts = cur_privileges.get('db_{}_hosts'.format(db), [])
            hosts = attrs['hosts']

            # find missing; and deleted
            deleted = [val for val in cur_hosts if val not in hosts]
            added = [val for val in hosts if val not in cur_hosts]

            for host in deleted:
                run_sql(node, generate_delete_db_priv_sql(user=user, db=db, host=host))

            for host in added:
                run_sql(node, generate_insert_db_priv_sql(user, db, host, priv, sql_available_db_privs))

            for host in hosts:
                run_sql(node, generate_update_db_priv_sql(user, db, host, priv, sql_available_db_privs))


def get_user(node, user, available_privs):
    users = {}
    sql = "SELECT Host, User, Password, {priv} FROM mysql.user WHERE User='{user}'".format(
        priv=", ".join(available_privs),
        user=user
    )
    res = run_sql(node, sql)
    if res is None:
        print(f'COULD NOT GET SQL QUERY: {sql} from {node}\n')
        return None

    for line in res.stdout.decode().split("\n")[1:]:
        if '\t' not in line:
            continue

        (host, user, password, *user_privileges) = line.split('\t')

        privileges = []
        for i in range(len(available_privs)):
            if user_privileges[i].upper() == 'Y':
                privileges.append(available_privs[i])

        if user not in users:
            users[user] = {}

        users[user][host] = {
            'user': user,
            'host': host,
            'password': password,
            'privileges': privileges,
        }

    if user not in users:
        return None

    user = users[user]
    hosts = sorted(list(user.keys()))

    password = None
    privileges = None
    for host in hosts:
        if password is not None and password != user[host]['password']:
            password = "THE_PASSWORD_IS_DIFFERENT_WE_WANT_A_NEW_ONE"
            break
        password = user[host]['password']

        if privileges is not None and privileges != user[host]['privileges']:
            privileges = []
            break
        privileges = user[host]['privileges']

    return {
        'password_hash': password,
        'privileges': privileges,
        'hosts': hosts,
    }


def get_user_privileges_for_dbs(node, user, available_db_privs):
    privileges = {}
    sql = "SELECT Host, Db, User, {priv} FROM mysql.db WHERE User='{user}'".format(
        priv=", ".join(available_db_privs),
        user=user
    )
    res = run_sql(node, sql)
    if res is None:
        return None

    for line in res.stdout.decode().split("\n")[1:]:
        if '\t' not in line:
            continue

        (host, db, user, *db_privileges) = line.split('\t')

        user_host_db_privileges = []
        for i in range(len(available_db_privs)):
            if db_privileges[i].upper() == 'Y':
                user_host_db_privileges.append(available_db_privs[i])

        if user not in privileges:
            privileges[user] = {}

        if db not in privileges[user]:
            privileges[user][db] = {}

        privileges[user][db][host] = {
            'user': user,
            'db': db,
            'host': host,
            'privileges': user_host_db_privileges,
        }

    if user not in privileges:
        return {
            'db_priv': [],
        }

    user = privileges[user]
    dbs = sorted(list(user.keys()))
    return_value = {
        'db_priv': dbs,
    }

    for db in dbs:
        return_value['db_{}_hosts'.format(db)] = []
        privileges = None
        for host in user[db].keys():
            if privileges is not None and privileges != user[db][host]['privileges']:
                privileges = []
                break
            privileges = user[db][host]['privileges']
            return_value['db_{}_hosts'.format(db)].append(host)

        return_value['db_{}_priv'.format(db)] = privileges

    return return_value


class MysqlUser(Item):
    """
    A MySql User.
    """
    BUNDLE_ATTRIBUTE_NAME = "mysql_users"
    NEEDS_STATIC = [
        "pkg_apt:",
        "pkg_pacman:",
        "pkg_yum:",
        "pkg_zypper:",
    ]
    ITEM_ATTRIBUTES = {
        'delete': False,
        'password': None,
        'password_hash': '',
        'privileges': [],
        'superuser': False,
        'hosts': ['127.0.0.1', '::1', 'localhost'].copy(),
        'db_priv': None,
    }
    ITEM_TYPE_NAME = "mysql_user"
    REQUIRED_ATTRIBUTES = []

    def __repr__(self):
        return "<MySqlRole name:{}>".format(self.name)

    def fix(self, status):
        if status.must_be_deleted:
            delete_user(self.node, self.name)
            # delete_db_priv(self.node, self.name)
        elif status.must_be_created:
            fix_user(self.node, self.name, self.attributes, self.available_privs, self.sql_available_privs, create=True)
            fix_db_priv(self.node, self.name, self.attributes, self.available_db_privs, self.sql_available_db_privs,
                        create=True)
        else:
            fix_user(self.node, self.name, self.attributes, self.available_privs, self.sql_available_privs)
            fix_db_priv(self.node, self.name, self.attributes, self.available_db_privs, self.sql_available_db_privs)

        flush_right(self.node)

    def cdict(self):
        if self.attributes['delete']:
            return None

        cdict = {
            'type': 'mysql_user',
            'password_hash': self.attributes['password_hash'],
            'privileges': self.attributes['privileges'],
            'hosts': self.attributes['hosts'],
            'db_priv': list(self.attributes.get('db_priv', {}).keys())
        }

        for db in self.attributes.get('db_priv', {}).keys():
            cdict['db_{}_priv'.format(db)] = self.attributes['db_priv'][db]

        return cdict

    def sdict(self):
        user = get_user(self.node, self.name, self.available_privs)

        if not user:
            return None

        db_priv = get_user_privileges_for_dbs(self.node, self.name, self.available_db_privs)

        sdict = {
            'type': 'mysql_user',
            'password_hash': user['password_hash'],
            'privileges': user['privileges'],
            'hosts': user['hosts'],
            'db_priv': db_priv.get('db_priv', []),
        }

        # the keys for sdict and cdict must be the same
        for db in self.attributes.get('db_priv', {}).keys():
            sdict['db_{}_priv'.format(db)] = db_priv.get('db_{}_priv'.format(db), [])

        return sdict

    # noinspection PyAttributeOutsideInit
    def patch_attributes(self, attributes):
        # import privileges into class
        self.available_privs = AVAILABLE_PRIVS.copy()
        self.available_db_privs = AVAILABLE_DB_PRIVS.copy()
        self.sql_available_privs = SQL_AVAILABLE_PRIVS.copy()
        self.sql_available_db_privs = SQL_AVAILABLE_DB_PRIVS.copy()

        if self.node.os == 'debian' and self.node.os_version[0] >= 10:
            self.available_privs += [
                'Delete_history_priv',  # MariaDB > 1.5
            ]
            self.sql_available_privs['Delete_history_priv'] = 'DELETE HISTORY'  # MariaDB > 1.5

            self.available_db_privs += [
                'Delete_history_priv',  # MariaDB > 1.5
            ]

            self.sql_available_db_privs['Delete_history_priv'] = 'DELETE HISTORY'  # since MariaDB > 1.5

        if 'password' in attributes and attributes['password'] != '':
            attributes['password_hash'] = mysql_context.encrypt(
                force_text(attributes['password'])
            )
        # sort hosts, since they do not depent in order
        if 'hosts' in attributes:
            attributes['hosts'] = sorted(attributes['hosts'])

        if 'superuser' in attributes and attributes['superuser']:
            attributes['privileges'] = AVAILABLE_PRIVS.copy()

        if attributes.get('db_priv', None) is None:
            attributes['db_priv'] = {}

        if 'db_priv' in attributes:
            for db, rights in attributes['db_priv'].items():
                if rights == 'all':
                    attributes['db_priv'][db] = self.available_db_privs.copy()
                elif type(attributes['db_priv'][db]) is not list:
                    attributes['db_priv'][db] = []

        return attributes

    def get_auto_deps(self, items):
        deps = []
        for item in items:
            if item.ITEM_TYPE_NAME == "mysql_db" and item.name in self.attributes.get('db_priv', {}).keys():
                if item.attributes.get('delete', False):
                    raise BundleError(_(
                        "{item1} (from bundle '{bundle1}') depends on item "
                        "{item2} (from bundle '{bundle2}') which is set to be deleted"
                    ).format(
                        item1=self.id,
                        bundle1=self.bundle.name,
                        item2=item.id,
                        bundle2=item.bundle.name,
                    ))
                else:
                    deps.append(item.id)
            # debian TODO: add other package manager
            if item.ITEM_TYPE_NAME == 'pkg_apt' and item.name == 'mysql-server':
                deps.append(item.id)
        return deps

    @classmethod
    def validate_attributes(cls, bundle, item_id, attributes):
        if not attributes.get('delete', False):
            if attributes.get('password') is None and attributes.get('password_hash') is None:
                raise BundleError(_(
                    "expected either 'password' or 'password_hash' on {item} in bundle '{bundle}'"
                ).format(
                    bundle=bundle.name,
                    item=item_id,
                ))
        if attributes.get('password') is not None and attributes.get('password_hash') is not None:
            raise BundleError(_(
                "can't define both 'password' and 'password_hash' on {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))
        if not isinstance(attributes.get('delete', True), bool):
            raise BundleError(_(
                "expected boolean for 'delete' on {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))

        if not isinstance(attributes.get('db_priv', {}), dict):
            raise BundleError(_(
                "expected dict for 'db_priv' on {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))

        for priv in attributes.get('privileges', []):
            if priv not in AVAILABLE_PRIVS:
                raise BundleError(_(
                    "privilege {priv} is not valid on {item} in bundle '{bundle}'"
                ).format(
                    priv=priv,
                    bundle=bundle.name,
                    item=item_id,
                ))
