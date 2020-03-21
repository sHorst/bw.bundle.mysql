@metadata_processor
def add_iptables_rules(metadata):
    if node.has_bundle('iptables'):
        allowed_hosts = set([])
        for user_name, mysql_config in metadata.get('mysql', {}).get('users', {}).items():
            allowed_hosts.update(mysql_config.get('allowed_hosts', []))

        for allowed_host in sorted(allowed_hosts):
            metadata += repo.libs.iptables.accept().chain('INPUT').source(allowed_host).tcp().dest_port(3306)

    return metadata, DONE


@metadata_processor
def add_restic_rules(metadata):
    if node.has_bundle('restic'):
        if 'restic' not in metadata:
            metadata['restic'] = {}

        if 'stdin_commands' not in metadata['restic']:
            metadata['restic']['stdin_commands'] = {}

        for db in metadata.get('mysql', {}).get('dbs', []):
            metadata['restic']['stdin_commands']['mysql_{}.sql'.format(db)] = \
                'mysqldump --defaults-extra-file=/etc/mysql/debian.cnf {}'.format(db)

    return metadata, DONE


@metadata_processor
def add_apt_packages(metadata):
    if node.has_bundle("apt"):
        metadata.setdefault('apt', {})
        metadata['apt'].setdefault('packages', {})

        if node.os == 'debian' and node.os_version[0] >= 10:
            # install mysql-server for current os
            metadata['apt']['packages']['mariadb-server'] = {'installed': True}
        else:
            # install mysql-server for current os
            metadata['apt']['packages']['mysql-server'] = {'installed': True}

    return metadata, DONE

