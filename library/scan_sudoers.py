#!/usr/bin/python

# Copyright: (c) 2019, Andrew J. Huffman <ahuffman@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: "scan_sudoers"
short_description: "Parses the /etc/sudoers and /etc/sudoers.d/* files."
version_added: "2.7"
author:
    - "Andrew J. Huffman (@ahuffman)"
description:
    - "This module is designed to collect information from C(/etc/sudoers).  The #include (files) and #includedir (directories) will be dynamically calculated and all included files will be parsed."
    - "This module is compatible with Linux and Unix systems."
'''

EXAMPLES = '''
- name: "Scan sudoers files"
  scan_sudoers:
'''

RETURN = '''
sudoers:
    description: "List of parsed sudoers data and included sudoers data"
    returned: "success"
    type: "list"
    sample:
      ansible_facts:
        sudoers:
          sudoers_files:
            - aliases:
                cmnd_alias:
                host_alias:
                runas_alias:
                user_alias:
              configuration:
                - 'Host_Alias        SOMEHOSTS = server1, server2'
                - ...
                - '#includedir /etc/sudoers.d'
              defaults:
                - '!visiblepw'
                - env_reset
                - secure_path:
                    - /usr/local/sbin
                    - /usr/local/bin
                    - /usr/sbin
                    - /usr/bin
                    - /sbin
                    - /bin
                - env_keep:
                    - COLORS
                    - DISPLAY
                    - ...
                - ...
              include_dir: /etc/sudoers.d
              included_files:
                - /etc/sudoers.d/file1
                - /etc/sudoers.d/file2
                - /tmp/some/file
                - ...
              path: /etc/sudoers
              user_specifications:
                - commands:
                    - ALL
                  hosts:
                    - ALL
                  operators:
                    - ALL
                  tags:
                    - NOPASSWD
                  users:
                    - '%wheel'
                - defaults:
                    - '!requiretty'
                  type: user
                  users:
                    - STAFF
                    - INTERNS
            - aliases:
                ...
'''

from ansible.module_utils.basic import AnsibleModule
import os
from os.path import isfile, join
import re

def main():
    module_args = dict()

    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    def get_options(path):
        ## Get includes
        sudoers_file = open(path, 'r')
        options = dict()
        options['included_files'] = list()
        include_dir = ""

        # Regex for "#includedir" and "#include" sudoers options
        includedir_re = re.compile(r'(^#includedir)+\s+(.*$)')
        include_re = re.compile(r'(^#include)+\s+(.*$)')

        for l in sudoers_file:
            line = l.replace('\n', '').replace('\t', '    ')
            # Search for '#includedir'
            if includedir_re.search(line):
                include_dir = includedir_re.search(line).group(2)
            # Search for '#include'
            if include_re.search(line):
                options['included_files'].append(include_re.search(line).group(2))
        sudoers_file.close()

        if include_dir:
            # build multi-file output
            options['include_dir'] = include_dir
            # Get list of all included sudoers files
            options['included_files'] += [join(include_dir, filename) for filename in os.listdir(include_dir) if isfile(join(include_dir, filename))]
        else:
            options['include_dir'] = include_dir
        return options

    def get_user_specs(line, path):
        user_spec = dict()
        user_spec_re =  re.compile(r'(^\S+,{1}\s*\S+|^\S+)\s*(\S+,{1}\s*|\S+){1}\s*={1}\s*((\S+,{1}\s*)+\S+|\S+){1}\s*(\S+:{1})*\s*(.*$)')
        default_override_re = re.compile(r'(Defaults){1}([@:!>]){1}((\s*\S+,{1})+\s*\S+|\S+)\s*(.*$)')
        spec_fields = user_spec_re.search(line)
        if user_spec_re.search(line):
            user_spec['tags'] = list()
            user_spec['commands'] = list()
            user_spec['users'] = list()
            user_spec['operators'] = list()
            user_spec['hosts'] = list()
            # users
            users = spec_fields.group(1).split(',')
            for user in users:
                if user != '' and user != None:
                    user_spec['users'].append(user.lstrip())
            # hosts
            hosts = spec_fields.group(2).split(',')
            for host in hosts:
                if host != '' and host != None:
                    user_spec['hosts'].append(host.lstrip())
            # operators
            operators = spec_fields.group(3).split(',')
            for op in operators:
                if op != '' and op != None:
                    user_spec['operators'].append(op.lstrip().replace('(', '').replace(')', ''))
            # tags - optional
            if spec_fields.group(5):
                tags = spec_fields.group(5).split(':')
                for tag in tags:
                    if tag != '' and tag != None:
                        user_spec['tags'].append(tag)
            # commands
            commands = spec_fields.group(6).split(',')
            for command in commands:
                if command != '' and command != None:
                    user_spec['commands'].append(command.lstrip())
            #user_spec['name'] = spec_fields.group(1)
        else:
            if default_override_re.search(line):
                default_override = default_override_re.search(line)
                # type
                if default_override.group(2) == '@':
                    user_spec['type'] = 'host'
                    user_spec['hosts'] = list()
                    hosts = default_override.group(3).split(',')
                    for host in hosts:
                        if host != '' and host != None:
                            user_spec['hosts'].append(host.lstrip())
                elif default_override.group(2) == ':':
                    user_spec['type'] = 'user'
                    user_spec['users'] = list()
                    users = default_override.group(3).split(',')
                    for user in users:
                        if user != '' and user != None:
                            user_spec['users'].append(user.lstrip())
                elif default_override.group(2) == '!':
                    user_spec['type'] = 'command'
                    user_spec['commands'] = list()
                    commands = default_override.group(3).split(',')
                    for command in commands:
                        if command != '' and command != None:
                            user_spec['commands'].append(command.lstrip())
                elif default_override.group(2) == '>':
                    user_spec['type'] = 'runas'
                    user_spec['operators'] = list()
                    operators = default_override.group(3).split(',')
                    for op in operators:
                        if op != '' and op != None:
                            user_spec['operators'].append(op.lstrip())
                user_spec['defaults'] = list()
                defaults = default_override.group(5).split(',')
                for default in defaults:
                    if default != '' and default != None:
                        user_spec['defaults'].append(default.lstrip())
        return user_spec

    def get_config_lines(path):
        # Read sudoers file
        all_lines = open(path, 'r')
        # Initialize empty return dict
        sudoer_file = dict()
        # Initialize aliases vars
        sudoer_aliases = dict()
        user_aliases = list()
        runas_aliases = list()
        host_aliases = list()
        command_aliases = list()
        user_specifications = list()
        # Raw config lines output
        config_lines = list()

        # Regex for Parsers
        comment_re = re.compile(r'^#+')
        include_re = re.compile(r'^#include')
        defaults_re = re.compile(r'^(Defaults)+\s+(.*$)')
        cmnd_alias_re = re.compile(r'^(Cmnd_Alias)+\s+(((.*)\s\=)+\s+(.*$))')
        host_alias_re = re.compile(r'^(Host_Alias)+\s+(((.*)\s\=)+\s+(.*$))')
        runas_alias_re = re.compile(r'^(Runas_Alias)+\s+(((.*)\s\=)+\s+(.*$))')
        user_alias_re = re.compile(r'^(User_Alias)+\s+(((.*)\s\=)+\s+(.*$))')

        # Defaults Parsing vars
        config_defaults = list()
        env_keep_opts = list()

        # Get options from file
        options = get_options(path)
        if options['included_files']:
            sudoer_file['included_files'] = options['included_files']
        else:
            sudoer_file['included_files'] = list()
        if options['include_dir']:
            sudoer_file['include_dir'] = options['include_dir']
        else:
            sudoer_file['include_dir'] = ""

        # Work on each line of sudoers file
        for l in all_lines:
            # All raw (non-comment) config lines out
            line = l.replace('\n', '').replace('\t', '    ') #cleaning up chars we don't want
            if comment_re.search(line) is None and line != '' and line != None:
                config_lines.append(line)
            if include_re.search(line):
                config_lines.append(line)

            # Parser for defaults
            if defaults_re.search(line):
                defaults_config_line = defaults_re.search(line).group(2)
                defaults_env_keep_re = re.compile(r'^(env_keep)+((\s\=)|(\s\+\=))+(\s)+(.*$)')
                defaults_sec_path_re = re.compile(r'^(secure_path)+(\s)+(\=)+(\s)+(.*$)')
                # Break up multi-line defaults config lines into single config options
                if defaults_env_keep_re.search(defaults_config_line):
                    defaults_multi = defaults_env_keep_re.search(defaults_config_line).group(6).split()
                    # env_keep default options
                    for i in defaults_multi:
                        env_keep_opts.append(i.replace('"', ''))
                # build secure path dict and append to defaults list
                elif defaults_sec_path_re.search(defaults_config_line):
                    secure_paths = defaults_sec_path_re.search(defaults_config_line).group(5).split(':')
                    config_defaults.append({'secure_path': secure_paths})
                # single defaults option case
                else:
                    config_defaults.append(defaults_config_line)
            # Aliases:
            # Parser for Command Alias
            if cmnd_alias_re.search(line):
                command_name = cmnd_alias_re.search(line).group(4)
                commands = list()
                for i in cmnd_alias_re.search(line).group(5).split(','):
                    # Append a space free item to the list
                    commands.append(i.replace(' ', ''))
                # Build command alias dict
                cmnd_alias_formatted = {'name': command_name, 'commands': commands}
                command_aliases.append(cmnd_alias_formatted)

            # Parser for Host Alias
            if host_alias_re.search(line):
                host_name = host_alias_re.search(line).group(4)
                hosts = list()
                for i in host_alias_re.search(line).group(5).split(','):
                    # Append a space free item to the list
                    hosts.append(i.replace(' ', ''))
                # Build command alias dict
                host_alias_formatted = {'name': host_name, 'hosts': hosts}
                host_aliases.append(host_alias_formatted)

            # Parser for RunAs Alias
            if runas_alias_re.search(line):
                runas_name = runas_alias_re.search(line).group(4)
                ra_users = list()
                for i in runas_alias_re.search(line).group(5).split(','):
                    # Append a space free item to the list
                    ra_users.append(i.replace(' ', ''))
                # Build command alias dict
                runas_alias_formatted = {'name': runas_name, 'users': ra_users}
                runas_aliases.append(runas_alias_formatted)

            # Parser for User Alias
            if user_alias_re.search(line):
                users_name = user_alias_re.search(line).group(4)
                ua_users = list()
                for i in user_alias_re.search(line).group(5).split(','):
                    # Append a space free item to the list
                    ua_users.append(i.replace(' ', ''))
                # Build command alias dict
                user_alias_formatted = {'name': users_name, 'users': ua_users}
                user_aliases.append(user_alias_formatted)

            # Parser for user_specs
            if not user_alias_re.search(line) and not runas_alias_re.search(line) and not host_alias_re.search(line) and not cmnd_alias_re.search(line) and not include_re.search(line) and not comment_re.search(line) and not defaults_re.search(line) and line != '' and line != None:
                user_spec = get_user_specs(line, path)
                user_specifications.append(user_spec)
        # Build the sudoer file's dict output
        sudoer_file['path'] = path
        sudoer_file['configuration'] = config_lines
        # Build defaults env_keep dict and append to the rest of the config_defaults list
        config_defaults.append({'env_keep': env_keep_opts})
        sudoer_file['defaults'] = config_defaults
        # Build aliases output dictionary
        sudoer_aliases = {'user_alias': user_aliases, 'runas_alias': runas_aliases, 'cmnd_alias': command_aliases, 'host_alias': host_aliases}
        sudoer_file['aliases'] = sudoer_aliases
        sudoer_file['user_specifications'] = user_specifications
        # done working on the file
        all_lines.close()
        return sudoer_file

    def get_sudoers_configs(path):
        sudoers = dict()
        included_files = list()

        # Get parsed values from default sudoers file
        sudoers['sudoers_files'] = list()
        default = get_config_lines(path)
        if default:
            sudoers['sudoers_files'].append(default)
        if default['included_files']:
            included_files += default['included_files']

        # Capture each included sudoer file
        for file in included_files:
            included_file = get_config_lines(file)
            if included_file:
                sudoers['sudoers_files'].append(included_file)
            # append even more included files as we parse deeper
            if included_file['included_files']:
                included_files += included_file['included_files']
        return sudoers

    default_sudoers = '/etc/sudoers'
    sudoers = get_sudoers_configs(default_sudoers)
    result = {'ansible_facts': {'sudoers': sudoers}}

    module.exit_json(**result)


if __name__ == '__main__':
    main()
