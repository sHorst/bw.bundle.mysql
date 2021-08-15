from bundlewrap.items import Item, ItemStatus
from bundlewrap.exceptions import BundleError, RemoteException
from passlib.apps import mysql_context
from bundlewrap.utils.text import force_text, mark_for_translation as _
import types

MYSQL_SCRIPT = "mysql --defaults-extra-file=/etc/mysql/debian.cnf information_schema"


def run_sql(node, sql):
    try:
        return node.run("echo \"{sql};\" | {mysql}".format(sql=sql, mysql=MYSQL_SCRIPT))
    except RemoteException:
        return None


def delete_database(node, name):
    run_sql(node, 'DROP DATABASE {}'.format(name))


def fix_database(node, name, attr, create=False):
    if create:
        collation = attr.get('collation', 'utf8_general_ci')
        character_set = attr.get('character_set', 'utf8')
        sql = "CREATE DATABASE \`{name}\` CHARACTER SET {character_set} COLLATE {collation}".format(
            name=name,
            character_set=character_set,
            collation=collation,
        )

        run_sql(node, sql)
    else:
        collation = attr.get('collation', 'utf8_general_ci')
        character_set = attr.get('character_set', 'utf8')
        sql = "ALTER DATABASE \`{name}\` CHARACTER SET {character_set} COLLATE {collation}".format(
            name=name,
            character_set=character_set,
            collation=collation,
        )

        run_sql(node, sql)


def get_database(node, name):
    databases = {}
    sql = "SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME " \
          "FROM SCHEMATA WHERE SCHEMA_NAME='{}'".format(name)

    res = run_sql(node, sql)
    if res is None:
        return None

    for line in res.stdout.decode().split("\n")[1:]:
        if '\t' not in line:
            continue

        (db, charset, collation) = line.split('\t')

        databases[db] = {
            'db': db,
            'collation': collation,
            'character_set': charset,
        }

    if name not in databases:
        return None

    db = databases[name]

    return db


class MysqlDb(Item):
    """
    A MySql Database.
    """
    BUNDLE_ATTRIBUTE_NAME = "mysql_dbs"
    NEEDS_STATIC = [
        "pkg_apt:",
        "pkg_pacman:",
        "pkg_yum:",
        "pkg_zypper:",
    ]
    ITEM_ATTRIBUTES = {
        'delete': False,
        'collation': 'utf8_general_ci',
        'character_set': 'utf8',
    }
    ITEM_TYPE_NAME = "mysql_db"
    REQUIRED_ATTRIBUTES = []

    def __repr__(self):
        return "<MySqlDb name:{}>".format(self.name)

    def fix(self, status):
        if status.must_be_deleted:
            delete_database(self.node, self.name)
        elif status.must_be_created:
            fix_database(self.node, self.name, self.attributes, create=True)
        else:
            fix_database(self.node, self.name, self.attributes)

    def cdict(self):
        if self.attributes['delete']:
            return None

        cdict = {
            'type': 'mysql_db',
            'collation': self.attributes['collation'],
            'character_set': self.attributes['character_set'],
        }

        return cdict

    def sdict(self):
        db = get_database(self.node, self.name)

        if not db:
            return None

        sdict = {
            'type': 'mysql_db',
            'collation': db.get('collation', 'utf8'),
            'character_set': db.get('character_set', 'utf8'),
        }

        return sdict

    @classmethod
    def validate_attributes(cls, bundle, item_id, attributes):
        if not isinstance(attributes.get('delete', True), bool):
            raise BundleError(_(
                "expected boolean for 'delete' on {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))

    def get_auto_deps(self, items):
        deps = []
        for item in items:
            # debian TODO: add other package manager
            if item.ITEM_TYPE_NAME == 'pkg_apt' and item.name == 'mysql-server':
                deps.append(item.id)
        return deps
