from ipaddress import ip_network

defaults = {}

# add apt packages
if node.has_bundle("apt"):
    defaults['apt'] = {
        'packages': {},
    }
    if node.os == 'debian' and node.os_version[0] >= 10:
        # install mariadb-server for current os
        defaults['apt']['packages']['mariadb-server'] = {'installed': True}
    else:
        # install mysql-server for current os
        defaults['apt']['packages']['mysql-server'] = {'installed': True}


@metadata_reactor
def add_iptables_rules(metadata):
    if not node.has_bundle('iptables'):
        raise DoNotRunAgain

    allowed_hosts = set([])
    for user_name, mysql_config in metadata.get('mysql/users', {}).items():
        for allowed_host in mysql_config.get('allowed_hosts', []):
            try:
                # check if nework is ip
                ip_network(allowed_host)
                allowed_hosts.add(allowed_host)
            except ValueError:
                pass

    iptables_rules = {}
    for allowed_host in sorted(allowed_hosts):
        iptables_rules += repo.libs.iptables.accept().chain('INPUT').source(allowed_host).tcp().dest_port(3306)

    return iptables_rules


@metadata_reactor
def add_restic_rules(metadata):
    if not node.has_bundle('restic'):
        raise DoNotRunAgain

    restic_cmd = {}
    for db in metadata.get('mysql/dbs', []):
        restic_cmd['mysql_{}.sql'.format(db)] = \
            'mysqldump --defaults-extra-file=/etc/mysql/debian.cnf {}'.format(db)

    return {
        'restic': {
            'stdin_commands': restic_cmd,
        }
    }
