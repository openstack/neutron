# Copyright (c) 2015 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""Implement ebtables rules using linux utilities."""

import re

from retrying import retry

from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import utils

ebtables_opts = [
    cfg.StrOpt('ebtables_path',
               default='$state_path/ebtables-',
               help=_('Location of temporary ebtables table files.')),
]

CONF = cfg.CONF
CONF.register_opts(ebtables_opts)

LOG = logging.getLogger(__name__)

# Collection of regexes to parse ebtables output
_RE_FIND_BRIDGE_TABLE_NAME = re.compile(r'^Bridge table:[\s]*([a-z]+)$')
# get chain name, nunmber of entries and policy name.
_RE_FIND_BRIDGE_CHAIN_INFO = re.compile(
    r'^Bridge chain:[\s]*(.*),[\s]*entries:[\s]*[0-9]+,[\s]*'
    r'policy:[\s]*([A-Z]+)$')
_RE_FIND_BRIDGE_RULE_COUNTERS = re.compile(
    r',[\s]*pcnt[\s]*=[\s]*([0-9]+)[\s]*--[\s]*bcnt[\s]*=[\s]*([0-9]+)$')
_RE_FIND_COMMIT_STATEMENT = re.compile(r'^COMMIT$')
_RE_FIND_COMMENTS_AND_BLANKS = re.compile(r'^#|^$')
_RE_FIND_APPEND_RULE = re.compile(r'-A (\S+) ')

# Regexes to parse ebtables rule file input
_RE_RULES_FIND_TABLE_NAME = re.compile(r'^\*([a-z]+)$')
_RE_RULES_FIND_CHAIN_NAME = re.compile(r'^:(.*)[\s]+([A-Z]+)$')
_RE_RULES_FIND_RULE_LINE = re.compile(r'^\[([0-9]+):([0-9]+)\]')


def _process_ebtables_output(lines):
    """Process raw output of ebtables rule listing file.

    Empty lines and comments removed, ebtables listing output converted
    into ebtables rules.

    For example, if the raw ebtables list lines (input to this function) are:

        Bridge table: filter
        Bridge chain: INPUT, entries: 0, policy: ACCEPT
        Bridge chain: FORWARD, entries: 0, policy: ACCEPT
        Bridge chain: OUTPUT, entries: 0, policy: ACCEPT

    The output then will be:

        *filter
        :INPUT ACCEPT
        :FORWARD ACCEPT
        :OUTPUT ACCEPT
        COMMIT

    Key point: ebtables rules listing output is not the same as the rules
               format for setting new rules.

    """
    table = None
    chain = ''
    chains = []
    rules = []

    for line in lines:
        if _RE_FIND_COMMENTS_AND_BLANKS.search(line):
            continue
        match = _RE_FIND_BRIDGE_RULE_COUNTERS.search(line)
        if table and match:
            rules.append('[%s:%s] -A %s %s' % (match.group(1),
                                               match.group(2),
                                               chain,
                                               line[:match.start()].strip()))
        match = _RE_FIND_BRIDGE_CHAIN_INFO.search(line)
        if match:
            chains.append(':%s %s' % (match.group(1), match.group(2)))
            chain = match.group(1)
            continue
        match = _RE_FIND_BRIDGE_TABLE_NAME.search(line)
        if match:
            table = '*%s' % match.group(1)
            continue
    return [table] + chains + rules + ['COMMIT']


def _match_rule_line(table, line):
    match = _RE_RULES_FIND_RULE_LINE.search(line)
    if table and match:
        args = line[match.end():].split()
        res = [(table, args)]
        if int(match.group(1)) > 0 and int(match.group(2)) > 0:
            p = _RE_FIND_APPEND_RULE
            rule = p.sub(r'-C \1 %s %s ', line[match.end() + 1:])
            args = (rule % (match.group(1), match.group(2))).split()
            res.append((table, args))
        return table, res
    else:
        return table, None


def _match_chain_name(table, tables, line):
    match = _RE_RULES_FIND_CHAIN_NAME.search(line)
    if table and match:
        if match.group(1) not in tables[table]:
            args = ['-N', match.group(1), '-P', match.group(2)]
        else:
            args = ['-P', match.group(1), match.group(2)]
        return table, (table, args)
    else:
        return table, None


def _match_table_name(table, line):
    match = _RE_RULES_FIND_TABLE_NAME.search(line)
    if match:
        # Initialize with current kernel table if we just start out
        table = match.group(1)
        return table, (table, ['--atomic-init'])
    else:
        return table, None


def _match_commit_statement(table, line):
    match = _RE_FIND_COMMIT_STATEMENT.search(line)
    if table and match:
        # Conclude by issuing the commit command
        return (table, ['--atomic-commit'])
    else:
        return None


def _process_ebtables_input(lines):
    """Import text ebtables rules. Similar to iptables-restore.

    Was based on:
    http://sourceforge.net/p/ebtables/code/ci/
    3730ceb7c0a81781679321bfbf9eaa39cfcfb04e/tree/userspace/ebtables2/
    ebtables-save?format=raw

    The function prepares and returns a list of tuples, each tuple consisting
    of a table name and ebtables arguments. The caller can then repeatedly call
    ebtables on that table with those arguments to get the rules applied.

    For example, this input:

        *filter
        :INPUT ACCEPT
        :FORWARD ACCEPT
        :OUTPUT ACCEPT
        :neutron-nwfilter-spoofing-fallb ACCEPT
        :neutron-nwfilter-OUTPUT ACCEPT
        :neutron-nwfilter-INPUT ACCEPT
        :neutron-nwfilter-FORWARD ACCEPT
        [0:0] -A INPUT -j neutron-nwfilter-INPUT
        [0:0] -A OUTPUT -j neutron-nwfilter-OUTPUT
        [0:0] -A FORWARD -j neutron-nwfilter-FORWARD
        [0:0] -A neutron-nwfilter-spoofing-fallb -j DROP
        COMMIT

    ... produces this output:

        ('filter', ['--atomic-init'])
        ('filter', ['-P', 'INPUT', 'ACCEPT'])
        ('filter', ['-P', 'FORWARD', 'ACCEPT'])
        ('filter', ['-P', 'OUTPUT', 'ACCEPT'])
        ('filter', ['-N', 'neutron-nwfilter-spoofing-fallb', '-P', 'ACCEPT'])
        ('filter', ['-N', 'neutron-nwfilter-OUTPUT', '-P', 'ACCEPT'])
        ('filter', ['-N', 'neutron-nwfilter-INPUT', '-P', 'ACCEPT'])
        ('filter', ['-N', 'neutron-nwfilter-FORWARD', '-P', 'ACCEPT'])
        ('filter', ['-A', 'INPUT', '-j', 'neutron-nwfilter-INPUT'])
        ('filter', ['-A', 'OUTPUT', '-j', 'neutron-nwfilter-OUTPUT'])
        ('filter', ['-A', 'FORWARD', '-j', 'neutron-nwfilter-FORWARD'])
        ('filter', ['-A', 'neutron-nwfilter-spoofing-fallb', '-j', 'DROP'])
        ('filter', ['--atomic-commit'])

    """
    tables = {'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
              'nat': ['PREROUTING', 'OUTPUT', 'POSTROUTING'],
              'broute': ['BROUTING']}
    table = None

    ebtables_args = list()
    for line in lines.splitlines():
        if _RE_FIND_COMMENTS_AND_BLANKS.search(line):
            continue
        table, res = _match_rule_line(table, line)
        if res:
            ebtables_args.extend(res)
            continue
        table, res = _match_chain_name(table, tables, line)
        if res:
            ebtables_args.append(res)
            continue
        table, res = _match_table_name(table, line)
        if res:
            ebtables_args.append(res)
            continue
        res = _match_commit_statement(table, line)
        if res:
            ebtables_args.append(res)
            continue

    return ebtables_args


@retry(wait_exponential_multiplier=1000, wait_exponential_max=10000,
       stop_max_delay=10000)
def _cmd_retry(func, *args, **kwargs):
    return func(*args, **kwargs)


def run_ebtables(namespace, execute, table, args):
    """Run ebtables utility, with retry if necessary.

    Provide table name and list of additional arguments to ebtables.

    """
    cmd = ['ebtables', '-t', table]
    if CONF.ebtables_path:
        f = '%s%s' % (CONF.ebtables_path, table)
        cmd += ['--atomic-file', f]
    cmd += args
    if namespace:
        cmd = ['ip', 'netns', 'exec', namespace] + cmd
    # TODO(jbrendel): The root helper is used for every ebtables command,
    #                 but as we use an atomic file we only need root for
    #                 init and commit commands.
    #                 But the generated file by init ebtables command is
    #                 only readable and writable by root.
    #
    # We retry the execution of ebtables in case of failure. Known issue:
    # See bug:    https://bugs.launchpad.net/nova/+bug/1316621
    # See patch:  https://review.openstack.org/#/c/140514/3
    return _cmd_retry(execute, cmd, **{"run_as_root": True})


def run_ebtables_multiple(namespace, execute, arg_list):
    """Run ebtables utility multiple times.

    Similar to run(), but runs ebtables for every element in arg_list.
    Each arg_list element is a tuple containing the table name and a list
    of ebtables arguments.

    """
    for table, args in arg_list:
        run_ebtables(namespace, execute, table, args)


@utils.synchronized('ebtables', external=True)
def ebtables_save(execute, tables_names, namespace=None):
    """Generate text output of the ebtables rules.

    Based on:
    http://sourceforge.net/p/ebtables/code/ci/master/tree/userspace/ebtables2/
    ebtables-save?format=raw

    """
    raw_outputs = (run_ebtables(namespace, execute,
                   t, ['-L', '--Lc']).splitlines() for t in tables_names)
    parsed_outputs = (_process_ebtables_output(lines) for lines in raw_outputs)
    return '\n'.join(l for lines in parsed_outputs for l in lines)


@utils.synchronized('ebtables', external=True)
def ebtables_restore(lines, execute, namespace=None):
    """Import text ebtables rules and apply."""
    ebtables_args = _process_ebtables_input(lines)
    run_ebtables_multiple(namespace, execute, ebtables_args)
