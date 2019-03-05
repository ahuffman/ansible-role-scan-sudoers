#!/usr/bin/python

# Copyright: (c) 2019, Andrew J. Huffman <ahuffman@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: scan_sudoers
short_description: "Parses the /etc/sudoers and /etc/sudoers.d/* files."
version_added: "2.7"
author:
    - "Andrew J. Huffman (@ahuffman)"
description:
    - "This module is designed to collect information from C(/etc/sudoers).  The includedir will be dynamically calculated and all included files will be parsed."
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
    sample: "[{WIP}]"
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

    def get_config_lines(path):
        all_lines = open(path, 'r')
        config_lines = list()
        sudoer_file = dict()
        comment_re = re.compile(r'^#+')
        defaults_re = re.compile(r'^(Defaults)+(\s)+(.*$)')
        config_defaults = list()
        env_keep_opts = list()
        for l in all_lines:
            # All raw (non-comment) config lines out
            line = l.replace('\n', '').replace('\t', '    ')
            if comment_re.search(line) is None and line != '' and line != None:
                config_lines.append(line)
            # Parser for defaults
            if defaults_re.search(line):
                defaults_config_line = defaults_re.search(line).group(3)
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
                    config_defaults.append({defaults_sec_path_re.search(defaults_config_line).group(1): defaults_sec_path_re.search(defaults_config_line).group(5)})
                # single defaults option case
                else:
                    config_defaults.append(defaults_config_line)
            # TODO Aliases:
            # Parser for User

            # Parser for RunAs

            # Parser for Host

            # Parser for Command

            # WIP...
        sudoer_file['path'] = path
        sudoer_file['configuration'] = config_lines
        # build sudoers defaults dict
        #   build env_keep dict and append to defaults list
        config_defaults.append({'env_keep': env_keep_opts})
        sudoer_file['defaults'] = config_defaults
        all_lines.close()
        return sudoer_file

    def get_sudoers_configs(path):
        # Get include dir from default sudoers
        sudoers_file = open(path, 'r')
        include_re = re.compile(r'(^#includedir)(\s)+(.*$)')
        for l in sudoers_file:
            line = l.replace('\n', '').replace('\t', '    ')
            if include_re.search(line):
                include_dir = include_re.search(line).group(3)
        sudoers_file.close()
        # build multi-file output
        sudoers = dict()
        sudoers['include_dir'] = include_dir
        sudoers['sudoers_files'] = list()
        # Capture default sudoers file
        sudoers['sudoers_files'].append(get_config_lines(path))
        # Get list of all included sudoers files
        sudoers['included_files'] = [ join(include_dir, filename) for filename in os.listdir(include_dir) if isfile(join(include_dir, filename))]
        # Capture each included sudoer file
        for file in sudoers['included_files']:
            sudoers['sudoers_files'].append(get_config_lines(file))
        return sudoers

    default_sudoers = '/etc/sudoers'
    sudoers = get_sudoers_configs(default_sudoers)
    output = {'sudoers': sudoers}
    result = {'ansible_facts': output}

    module.exit_json(**result)


if __name__ == '__main__':
    main()
