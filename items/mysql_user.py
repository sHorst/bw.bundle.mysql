from bundlewrap.items import Item, ItemStatus
from bundlewrap.exceptions import BundleError
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
    'Create_tablespace_priv'
]

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

MYSQL_SCRIPT = "mysql --defaults-extra-file=/etc/mysql/debian.cnf"


def run_sql(node, sql):
    return node.run("echo \"{sql};\" | {mysql}".format(sql=sql, mysql=MYSQL_SCRIPT))


def flush_right(node):
    return run_sql(node, "FLUSH PRIVILEGES")


def delete_user(node, user):
    run_sql(node, "DELETE FROM mysql.user WHERE User='{user}';".format(user=user))


def delete_db_priv(node, user):
    run_sql(node, "DELETE FROM mysql.db WHERE User='{user}';".format(user=user))


def generate_insert_user_sql(user, host, password, priv):
    # sql = "INSERT INTO mysql.user " \
    #       "(Host, User, Password, {priv_fields}, ssl_type, ssl_cipher, x509_issuer, x509_subject, " \
    #       "max_questions, max_updates, max_connections, max_user_connections, plugin, authentication_string, " \
    #       "password_expired, is_role, default_role, max_statement_time) VALUES " \
    #       "('{host}' ,'{user}', '{password}', '{priv}', '', '', '', ''," \
    #       "0, 0, 0, 0, '', '', 'N', 'N', '', '0.0000')".format(
    #             host=host,
    #             user=user,
    #             password=password,
    #             priv_fields=', '.join(priv.keys()),
    #             priv="', '".join(priv.values())
    #       )
    sql = "INSERT INTO mysql.user " \
          "(Host, User, Password, {priv_fields}, ssl_type, ssl_cipher, x509_issuer, x509_subject, " \
          "max_questions, max_updates, max_connections, max_user_connections, plugin, authentication_string) " \
          "VALUES " \
          "('{host}' ,'{user}', '{password}', '{priv}', '', '', '', ''," \
          "0, 0, 0, 0, '', '')".format(
        host=host,
        user=user,
        password=password,
        priv_fields=', '.join(priv.keys()),
        priv="', '".join(priv.values())
    )

    return sql


def generate_update_user_sql(user, password, priv):
    priv_list = []
    for key in priv.keys():
        priv_list.append("{} = '{}'".format(key, priv[key]))

    sql = "UPDATE mysql.user SET " \
          "Password='{password}', {priv} WHERE User = '{user}'".format(
                password=password,
                priv=', '.join(priv_list),
                user=user,
          )

    return sql


def generate_delete_user_sql(user, host):
    sql = "DELETE FROM mysql.user WHERE User='{user}' and Host='{host}';".format(user=user, host=host)

    return sql


def generate_insert_db_priv_sql(user, db, host, priv):
    sql = "INSERT INTO mysql.db " \
          "(Host, Db, User, {priv_fields}) VALUES " \
          "('{host}' ,'{db}', '{user}', '{priv}')".format(
                host=host,
                db=db,
                user=user,
                priv_fields=', '.join(priv.keys()),
                priv="', '".join(priv.values())
          )

    return sql


def generate_update_db_priv_sql(user, db, priv):
    priv_list = []
    for key in priv.keys():
        priv_list.append("{} = '{}'".format(key, priv[key]))

    sql = "UPDATE mysql.db SET " \
          "{priv} WHERE User = '{user}' AND Db = '{db}'".format(
                priv=', '.join(priv_list),
                user=user,
                db=db,
          )

    return sql


def generate_delete_db_priv_sql(user, db, host):
    sql = "DELETE FROM mysql.db WHERE " \
          "User='{user}' AND Db='{db}' AND Host='{host}';".format(user=user, db=db, host=host)

    return sql


def fix_user(node, user, attrs, create=False):
    password = attrs['password_hash']

    priv = {}
    for cur_priv in AVAILABLE_PRIVS:
        priv[cur_priv] = "Y" if cur_priv in attrs['privileges'] else 'N'

    if create:
        for host in attrs['hosts']:
            sql = generate_insert_user_sql(user, host, password, priv)

            run_sql(node, sql)
    else:
        cur_hosts = get_user(node, user)['hosts']
        hosts = attrs['hosts']

        # find missing; and deleted
        deleted = [val for val in cur_hosts if val not in hosts]
        added = [val for val in hosts if val not in cur_hosts]

        for host in deleted:
            run_sql(node, generate_delete_user_sql(user=user, host=host))

        for host in added:
            run_sql(node, generate_insert_user_sql(user, host, password, priv))

        run_sql(node, generate_update_user_sql(user, password, priv))


def fix_db_priv(node, user, attrs, create=False):
    if create:
        for db in attrs['db_priv']:
            priv = {}
            for cur_priv in AVAILABLE_DB_PRIVS:
                priv[cur_priv] = "Y" if cur_priv in attrs['db_priv'][db] else 'N'

            # create new privileges for this db for all hosts
            for host in attrs['hosts']:
                sql = generate_insert_db_priv_sql(user, db, host, priv)
                run_sql(node, sql)
    else:
        cur_privileges = get_user_privileges_for_dbs(node, user)

        for db in attrs['db_priv']:
            priv = {}
            for cur_priv in AVAILABLE_DB_PRIVS:
                priv[cur_priv] = "Y" if cur_priv in attrs['db_priv'][db] else 'N'

            cur_hosts = cur_privileges.get('db_{}_hosts'.format(db), [])
            hosts = attrs['hosts']

            # find missing; and deleted
            deleted = [val for val in cur_hosts if val not in hosts]
            added = [val for val in hosts if val not in cur_hosts]

            for host in deleted:
                run_sql(node, generate_delete_db_priv_sql(user=user, db=db, host=host))

            for host in added:
                run_sql(node, generate_insert_db_priv_sql(user, db, host, priv))

            run_sql(node, generate_update_db_priv_sql(user, db, priv))


def get_user(node, user):
    users = {}
    sql = "SELECT Host, User, Password, {priv} FROM mysql.user WHERE User='{user}'".format(
        priv=", ".join(AVAILABLE_PRIVS),
        user=user
    )
    res = run_sql(node, sql)

    for line in res.stdout.decode().split("\n")[1:]:
        if '\t' not in line:
            continue

        (host, user, password, *user_privileges) = line.split('\t')

        privileges = []
        for i in range(len(AVAILABLE_PRIVS)):
            if user_privileges[i].upper() == 'Y':
                privileges.append(AVAILABLE_PRIVS[i])

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


def get_user_privileges_for_dbs(node, user):
    privileges = {}
    sql = "SELECT Host, Db, User, {priv} FROM mysql.db WHERE User='{user}'".format(
        priv=", ".join(AVAILABLE_DB_PRIVS),
        user=user
    )
    res = run_sql(node, sql)

    for line in res.stdout.decode().split("\n")[1:]:
        if '\t' not in line:
            continue

        (host, db, user, *db_privileges) = line.split('\t')

        user_host_db_privileges = []
        for i in range(len(AVAILABLE_DB_PRIVS)):
            if db_privileges[i].upper() == 'Y':
                user_host_db_privileges.append(AVAILABLE_DB_PRIVS[i])

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
            delete_db_priv(self.node, self.name)
        elif status.must_be_created:
            fix_user(self.node, self.name, self.attributes, create=True)
            fix_db_priv(self.node, self.name, self.attributes, create=True)
        else:
            fix_user(self.node, self.name, self.attributes)
            fix_db_priv(self.node, self.name, self.attributes)

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
        user = get_user(self.node, self.name)

        if not user:
            return None

        db_priv = get_user_privileges_for_dbs(self.node, self.name)

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

    def patch_attributes(self, attributes):
        if 'password' in attributes and attributes['password'] is not '':
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
                    attributes['db_priv'][db] = AVAILABLE_DB_PRIVS.copy()
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
