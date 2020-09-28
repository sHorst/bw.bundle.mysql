@metadata_reactor
def add_iptables_rules(metadata):
    if not node.has_bundle('iptables'):
        raise DoNotRunAgain

    iptables_rules = {}
    allowed_hosts = set([])
    for user_name, mysql_config in metadata.get('mysql/users', {}).items():
        allowed_hosts.update(mysql_config.get('allowed_hosts', []))

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
