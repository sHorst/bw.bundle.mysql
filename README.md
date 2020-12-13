Mysql Modul
-----------

This module checks the METADATA for mysql tables and users and applies them.

Install
-------

To make this bundle work, you need to insert the items/mysql_db.py and items/mysql_user.py to the bw repository. This can be done with this command:

```
ln -s ../bundles/mysql/items/mysql_db.py items/mysql_db.py
ln -s ../bundles/mysql/items/mysql_user.py items/mysql_user.py
```

Dependencies
------------
Packages defined in ```metadata.py``` and installed via [apt-Bundle](https://github.com/sHorst/bw.bundle.apt).

Demo Metadata
-------------

```python
metadata = {
    'mysql': {
        'users': {
            'user_name': {
                'password': 'password', 
                'allowed_hosts': ['localhost', '12.34.56.78'],
                'db_priv': {
                    'db_1': ['Select_priv', ],
                    'db_2': ['Select_priv', 'Create_tmp_table_priv', 'Create_view_priv', 'Show_view_priv', ],
                },
            },
        },
        'dbs': {
            'db_1': {
                'collation': 'utf8_unicode_ci',
                'character_set': 'utf8',
            },
            'db_2': {
                'collation': 'utf8_unicode_ci',
                'character_set': 'utf8',
            },
        }
    },
}
```