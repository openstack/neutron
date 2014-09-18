# Copyright (c) 2013 OpenStack Foundation.
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
# @author: Edouard Thuleau, Cloudwatt.
# based on
#   neutron/agent/linux/iptables_manager.py

"""Implements ebtables rules using linux utilities."""

import inspect
import os
import re

from oslo.config import cfg

from neutron.agent.linux import utils as linux_utils
from neutron.common import utils
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


ebtables_opts = [
    cfg.StrOpt('ebtables_path',
               default='$state_path/ebtables-',
               help=_('Location of temporary ebtables table files.')),
]


CONF = cfg.CONF
CONF.register_opts(ebtables_opts)


@utils.synchronized('ebtables', external=True)
def ebtables_save(execute, root_helper, namespace=None, tables=None):
    """Generates text output of the ebtables rules.

    Based on:
    http://sourceforge.net/p/ebtables/code/ci/master/tree/userspace/ebtables2/
    ebtables-save?format=raw

    """

    if not tables:
        tables = ['filter', 'nat', 'broute']
    ebtables_save = ""

    def _process_table(lines):
        table = None
        chains = ''
        chain = ''
        rules = ''

        exprs = {'table': re.compile(r'^Bridge table: ([a-z]+)$'),
                 'chain': re.compile(r'^Bridge chain: (.*), entries: [0-9]+, '
                                     'policy: ([A-Z]+)$'),
                 'rule': re.compile(r', pcnt = ([0-9]+) -- bcnt = ([0-9]+)$'),
                 'comment_or_blank': re.compile(r'^#|^$')}

        for line in lines:
            if exprs['comment_or_blank'].search(line):
                continue
            match = exprs['rule'].search(line)
            if table and match:
                rules += '[%s:%s] -A %s %s\n' % (match.group(1),
                                                 match.group(2),
                                                 chain,
                                                 line[:match.start()].strip())
            match = exprs['chain'].search(line)
            if match:
                chains += ':%s %s\n' % (match.group(1), match.group(2))
                chain = match.group(1)
                continue
            match = exprs['table'].search(line)
            if match:
                table = '*%s\n' % match.group(1)
                continue
        return table + chains + rules + 'COMMIT\n'

    for table in tables:
        args = ['ebtables', '-t', table, '-L', '--Lc']
        if namespace:
            args = ['ip', 'netns', 'exec', namespace] + args
        lines = execute(args, root_helper=root_helper).split('\n')

        ebtables_save += _process_table(lines)
    return ebtables_save[:-1]


@utils.synchronized('ebtables', external=True)
def ebtables_restore(lines, ebtables_path, execute, root_helper,
                     namespace=None):
    """Imports text ebtables rules. Similar to iptables-restore.

    Based on:
    http://sourceforge.net/p/ebtables/code/ci/
    3730ceb7c0a81781679321bfbf9eaa39cfcfb04e/tree/userspace/ebtables2/
    ebtables-save?format=raw
    """
    tables = {'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
              'nat': ['PREROUTING', 'OUTPUT', 'POSTROUTING'],
              'broute': ['BROUTING']}
    cur_table = None

    def _run_ebtables_cmd(table, args):
        cmd = ['ebtables', '-t', table]
        f = ('%s%s') % (ebtables_path, table)
        cmd = ['EBTABLES_ATOMIC_FILE=%s' % f, 'ebtables', '-t', table] + args
        if namespace:
            cmd = ['ip', 'netns', 'exec', namespace] + cmd
        # TODO(ethuleau): the root helper is use for every ebtables command,
        #                 but as we use an atomic file we only need root for
        #                 init and commit commands.
        #                 But the generated file by init ebtables command is
        #                 only readable and writable by root.
        execute(cmd, root_helper=root_helper)

    exprs = {'table': re.compile(r'^\*([a-z]+)$'),
             'chain': re.compile(r'^:(.*) ([A-Z]+)$'),
             'rule': re.compile(r'^\[([0-9]+):([0-9]+)\]'),
             'commit': re.compile(r'^COMMIT$'),
             'comment_or_blank': re.compile(r'^#|^$')}

    for line in lines.split('\n'):
        if exprs['comment_or_blank'].search(line):
            continue
        match = exprs['rule'].search(line)
        if cur_table and match:
            args = line[match.end():].split()
            _run_ebtables_cmd(cur_table, args)
            if int(match.group(1)) > 0 and int(match.group(2)) > 0:
                p = re.compile('^-A (\S+) ')
                rule = p.sub(r'-C \1 %s %s ', line[match.end() + 1:])
                args = (rule % (match.group(1), match.group(2))).split()
                _run_ebtables_cmd(cur_table, args)
            continue
        match = exprs['chain'].search(line)
        if cur_table and match:
            if match.group(1) not in tables[cur_table]:
                args = ['-N', match.group(1), '-P', match.group(2)]
                _run_ebtables_cmd(cur_table, args)
            else:
                args = ['-P', match.group(1), match.group(2)]
                _run_ebtables_cmd(cur_table, args)
            continue
        match = exprs['table'].search(line)
        if match:
            cur_table = match.group(1)
            _run_ebtables_cmd(cur_table, ['--atomic-init'])
            continue
        match = exprs['commit'].search(line)
        if cur_table and match:
            _run_ebtables_cmd(cur_table, ['--atomic-commit'])
            continue


class ChainName(object):
    """Mixin to manage the prefix name and the chain name length in function of
    the prefix name length.
    """
    MAX_CHAIN_LEN_EBTABLES = 31
    # NOTE(ethuleau): ebtables supports chain names of up to 31 characters, and
    #                 we add up to 12 characters to prefix_chain which is used
    #                 as a prefix, so we limit it to 19 characters.
    MAX_LEN_PREFIX_CHAIN = MAX_CHAIN_LEN_EBTABLES - len('-POSTROUTING')

    @classmethod
    def binary_name(cls):
        """Grab the name of the binary we're running in."""
        return os.path.basename(inspect.stack()[-1][1])

    def _get_prefix_chain(self, prefix_chain=None):
        """Determine the prefix chain."""
        if hasattr(self, 'prefix_chain'):
            return self.prefix_chain[:self.MAX_LEN_PREFIX_CHAIN]
        elif prefix_chain:
            return prefix_chain[:self.MAX_LEN_PREFIX_CHAIN]
        else:
            return self.binary_name()[:self.MAX_LEN_PREFIX_CHAIN]

    def _get_max_chain_len_wrap(self, prefix_chain=None):
        """Get the possible chain name length in function of the prefix name
        length.
        """
        return (self.MAX_CHAIN_LEN_EBTABLES -
                (len(self._get_prefix_chain(prefix_chain)) + len('-')))

    def _get_max_chain_len_nowrap(self):
        """Get the maximun ebtables chain name length."""
        return self.MAX_CHAIN_LEN_EBTABLES

    def get_chain_name(self, chain_name, wrap=True, prefix_chain=None):
        """Determine the chain name."""
        if wrap:
            return chain_name[:self._get_max_chain_len_wrap(prefix_chain)]
        else:
            return chain_name[:self._get_max_chain_len_nowrap()]


class EbtablesRule(ChainName):
    """An ebtables rule.

    You shouldn't need to use this class directly, it's only used by
    EbtablesManager.

    """

    def __init__(self, chain, rule, wrap=True, top=False,
                 prefix_chain=None):
        self.prefix_chain = self._get_prefix_chain(prefix_chain)
        self.chain = self.get_chain_name(chain, wrap, prefix_chain)
        self.rule = rule
        self.wrap = wrap
        self.top = top

    def __eq__(self, other):
        return ((self.chain == other.chain) and
                (self.rule == other.rule) and
                (self.top == other.top) and
                (self.wrap == other.wrap))

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        if self.wrap:
            chain = '%s-%s' % (self.prefix_chain, self.chain)
        else:
            chain = self.chain
        return '-A %s %s' % (chain, self.rule)


class EbtablesTable(ChainName):
    """An ebtables table."""

    def __init__(self, prefix_chain=None):
        self.rules = []
        self.remove_rules = []
        self.chains = set()
        self.unwrapped_chains = set()
        self.remove_chains = set()
        self.prefix_chain = self._get_prefix_chain(prefix_chain)

    def add_chain(self, name, wrap=True):
        """Adds a named chain to the table.

        The chain name is wrapped to be unique for the component creating
        it, so different components of Neutron can safely create identically
        named chains without interfering with one another.

        At the moment, its wrapped name is <prefix chain>-<chain name>,
        so if neutron-server creates a chain named 'OUTPUT', it'll actually
        end up named 'neutron-server-OUTPUT'.

        """
        name = self.get_chain_name(name, wrap, self.prefix_chain)
        if wrap:
            self.chains.add(name)
        else:
            self.unwrapped_chains.add(name)

    def _select_chain_set(self, wrap):
        if wrap:
            return self.chains
        else:
            return self.unwrapped_chains

    def ensure_remove_chain(self, name, wrap=True):
        """Ensure the chain is removed.

        This removal "cascades". All rule in the chain are removed, as are
        all rules in other chains that jump to it.
        """
        name = self.get_chain_name(name, wrap, self.prefix_chain)
        chain_set = self._select_chain_set(wrap)
        if name not in chain_set:
            return

        self.remove_chain(name, wrap)

    def remove_chain(self, name, wrap=True):
        """Remove named chain.

        This removal "cascades". All rule in the chain are removed, as are
        all rules in other chains that jump to it.

        If the chain is not found, this is merely logged.

        """
        name = self.get_chain_name(name, wrap, self.prefix_chain)
        chain_set = self._select_chain_set(wrap)

        if name not in chain_set:
            LOG.warn(_('Attempted to remove chain %s which does not exist'),
                     name)
            return

        chain_set.remove(name)

        if not wrap:
            # non-wrapped chains and rules need to be dealt with specially,
            # so we keep a list of them to be iterated over in apply()
            self.remove_chains.add(name)

            # first, add rules to remove that have a matching chain name
            self.remove_rules += [r for r in self.rules if r.chain == name]

        # next, remove rules from list that have a matching chain name
        self.rules = [r for r in self.rules if r.chain != name]

        if not wrap:
            jump_snippet = '-j %s' % name
            # next, add rules to remove that have a matching jump chain
            self.remove_rules += [r for r in self.rules
                                  if jump_snippet in r.rule]
        else:
            jump_snippet = '-j %s-%s' % (self.prefix_chain, name)

        # finally, remove rules from list that have a matching jump chain
        self.rules = [r for r in self.rules
                      if jump_snippet not in r.rule]

    def add_rule(self, chain, rule, wrap=True, top=False):
        """Add a rule to the table.

        This is just like what you'd feed to ebtables, just without
        the '-A <chain name>' bit at the start.

        However, if you need to jump to one of your wrapped chains,
        prepend its name with a '$' which will ensure the wrapping
        is applied correctly.

        """
        chain = self.get_chain_name(chain, wrap, self.prefix_chain)
        if wrap and chain not in self.chains:
            raise LookupError(_('Unknown chain: %r') % chain)

        if '$' in rule:
            rule = ' '.join(map(self._wrap_target_chain, rule.split(' ')))

        self.rules.append(EbtablesRule(chain, rule, wrap, top,
                                       self.prefix_chain))

    def remove_rule(self, chain, rule, wrap=True, top=False):
        """Remove a rule from a chain.

        However, if you the rule jumps to one of your wrapped chains,
        prepend its name with a '$' which will ensure the wrapping
        is applied correctly.
        """
        chain = self.get_chain_name(chain, wrap, self.prefix_chain)
        if '$' in rule:
            rule = ' '.join(map(self._wrap_target_chain, rule.split(' ')))

        try:
            self.rules.remove(EbtablesRule(chain, rule, wrap, top,
                                           self.prefix_chain))
            if not wrap:
                self.remove_rules.append(EbtablesRule(chain, rule, wrap, top,
                                                      self.prefix_chain))
        except ValueError:
            LOG.warn(_('Tried to remove rule that was not there:'
                       ' %(chain)r %(rule)r %(wrap)r %(top)r'),
                     {'chain': chain, 'rule': rule,
                      'top': top, 'wrap': wrap})

    def _wrap_target_chain(self, s):
        if s.startswith('$'):
            return ('%s-%s' % (self.prefix_chain, s[1:]))
        return s

    def empty_chain(self, chain, wrap=True):
        """Remove all rules from a chain."""
        chain = self.get_chain_name(chain, wrap, self.prefix_chain)
        chained_rules = [rule for rule in self.rules
                         if rule.chain == chain and rule.wrap == wrap]
        for rule in chained_rules:
            self.rules.remove(rule)


class EbtablesManager(ChainName):
    """Wrapper for ebtables.

    A number of chains are set up to begin with.

    The built-in chains of tables 'filter, nat and 'broute' are wrapped,
    meaning that the "real" INPUT chain of filter table has a rule that jumps
    to the wrapped INPUT chain, etc.

    """

    def __init__(self, _execute=None, root_helper=None, namespace=None,
                 prefix_chain=None):
        self.ebtables_path = CONF.ebtables_path
        if _execute:
            self.execute = _execute
        else:
            self.execute = linux_utils.execute

        self.iptables_apply_deferred = False
        self.root_helper = root_helper
        self.namespace = namespace
        self.prefix_chain = self._get_prefix_chain(prefix_chain)

        self.tables = {'filter': EbtablesTable(prefix_chain=self.prefix_chain)}
        self.tables.update(
            {'nat': EbtablesTable(prefix_chain=self.prefix_chain)})
        self.tables.update(
            {'broute': EbtablesTable(prefix_chain=self.prefix_chain)})

        builtin_chains = {'filter': ['INPUT', 'OUTPUT', 'FORWARD'],
                          'nat': ['PREROUTING', 'OUTPUT', 'POSTROUTING'],
                          'broute': ['BROUTING']}
        for table, chains in builtin_chains.iteritems():
            for chain in chains:
                self.tables[table].add_chain(chain)
                self.tables[table].add_rule(chain, '-j $%s' % (chain),
                                            wrap=False)

    def defer_apply_on(self):
        self.iptables_apply_deferred = True

    def defer_apply_off(self):
        self.iptables_apply_deferred = False
        self._apply()

    def apply(self):
        if self.iptables_apply_deferred:
            return

        self._apply()

    def _apply(self):
        """Apply the current in-memory set of ebtables rules.

        This will blow away any rules left over from previous runs of the
        same component of Neutron, and replace them with our current set of
        rules. This happens atomically, thanks to ebtables_save/restore.

        """
        tables = [table_name for table_name, table in self.tables.iteritems()]
        all_lines = ebtables_save(self.execute, self.root_helper,
                                  namespace=self.namespace,
                                  tables=tables).split('\n')

        for table_name, table in self.tables.iteritems():
            start, end = self._find_table(all_lines, table_name)
            all_lines[start:end] = self._modify_rules(all_lines[start:end],
                                                      table, table_name)
        ebtables_restore('\n'.join(all_lines), self.ebtables_path,
                         self.execute, self.root_helper,
                         namespace=self.namespace)
        LOG.debug(_("EbtablesManager.apply completed with success"))

    def _find_table(self, lines, table_name):
        if len(lines) < 3:
            # length only <2 when fake ebtables
            return (0, 0)
        try:
            start = lines.index('*%s' % table_name)
        except ValueError:
            # Couldn't find table_name
            LOG.debug(_('Unable to find table %s'), table_name)
            return (0, 0)
        end = lines[start:].index('COMMIT') + start + 1
        return (start, end)

    def _find_rules_index(self, lines):
        seen_chains = False
        rules_index = 0
        for rules_index, rule in enumerate(lines):
            if not seen_chains:
                if rule.startswith(':'):
                    seen_chains = True
            else:
                if not rule.startswith(':'):
                    break

        if not seen_chains:
            rules_index = 2

        return rules_index

    def _modify_rules(self, current_lines, table, table_name):
        unwrapped_chains = table.unwrapped_chains
        chains = table.chains
        remove_chains = table.remove_chains
        rules = table.rules
        remove_rules = table.remove_rules

        if not current_lines:
            fake_table = ['*' + table_name, 'COMMIT']
            current_lines = fake_table

        # Fill old_filter with any chains or rules we might have added,
        # they could have a [packet:byte] count we want to preserve.
        # Fill new_filter with any chains or rules without our name in them.
        old_filter, new_filter = [], []
        for line in current_lines:
            (old_filter if self.prefix_chain in line else
             new_filter).append(line.strip())

        #rules_index = self._find_rules_index(new_filter)

        # TODO(ethuleau): ebtables permits to define a policy to an
        #                 user-defined chains unlike iptables.
        #                 This first implementation set the chain policy to
        #                 ACCEPT by default. It needs to be updated.
        all_chains = [':%s ACCEPT' % name for name in unwrapped_chains]
        all_chains += [':%s-%s ACCEPT' % (self.prefix_chain, name)
                       for name in chains]

        # Iterate through all the chains, trying to find an existing
        # match.
        our_chains = []
        for chain in all_chains:
            chain_str = str(chain).strip()

            orig_filter = [s for s in old_filter if chain_str in s.strip()]
            dup_filter = [s for s in new_filter if chain_str in s.strip()]
            new_filter = [s for s in new_filter if chain_str not in s.strip()]

            # if no old or duplicates, use original chain
            if orig_filter:
                # grab the last entry, if there is one
                old = orig_filter[-1]
                chain_str = str(old).strip()
            elif dup_filter:
                # grab the last entry, if there is one
                dup = dup_filter[-1]
                chain_str = str(dup).strip()

            our_chains += [chain_str]

        # Iterate through all the rules, trying to find an existing
        # match.
        our_rules = []
        bot_rules = []
        for rule in rules:
            rule_str = str(rule).strip()
            # Further down, we weed out duplicates from the bottom of the
            # list, so here we remove the dupes ahead of time.

            orig_filter = [s for s in old_filter if rule_str in s.strip()]
            dup_filter = [s for s in new_filter if rule_str in s.strip()]
            new_filter = [s for s in new_filter if rule_str not in s.strip()]

            # if no old or duplicates, use original rule
            if orig_filter:
                # grab the last entry, if there is one
                old = orig_filter[-1]
                rule_str = str(old).strip()
            elif dup_filter:
                # grab the last entry, if there is one
                dup = dup_filter[-1]
                rule_str = str(dup).strip()
                # backup one index so we write the array correctly
                #rules_index -= 1
            else:
                # add-on the [packet:bytes]
                rule_str = '[0:0] ' + rule_str

            if rule.top:
                # rule.top == True means we want this rule to be at the top.
                our_rules += [rule_str]
            else:
                bot_rules += [rule_str]

        our_rules += bot_rules

        rules_index = self._find_rules_index(new_filter)
        new_filter[rules_index:rules_index] = our_rules
        new_filter[rules_index:rules_index] = our_chains

        def _strip_packets_bytes(line):
            # strip any [packet:bytes] counts at end of lines
            if line.startswith('['):
                # it's a rule, for example, "[0:0] -A neutron-billing..."
                line = line.split('] ', 1)[1]
            line = line.strip()
            return line

        seen_chains = set()

        def _weed_out_duplicate_chains(line):
            # ignore [packet:byte] counts at end of lines
            if line.startswith(':'):
                line = _strip_packets_bytes(line)
                if line in seen_chains:
                    return False
                else:
                    seen_chains.add(line)

            # Leave it alone
            return True

        seen_rules = set()

        def _weed_out_duplicate_rules(line):
            if line.startswith('['):
                line = _strip_packets_bytes(line)
                if line in seen_rules:
                    return False
                else:
                    seen_rules.add(line)

            # Leave it alone
            return True

        def _weed_out_removes(line):
            # We need to find exact matches here
            if line.startswith(':'):
                line = _strip_packets_bytes(line)
                for chain in remove_chains:
                    if chain == line:
                        remove_chains.remove(chain)
                        return False
            elif line.startswith('['):
                line = _strip_packets_bytes(line)
                for rule in remove_rules:
                    rule_str = _strip_packets_bytes(str(rule))
                    if rule_str == line:
                        remove_rules.remove(rule)
                        return False

            # Leave it alone
            return True

        # We filter duplicates.  Go throught the chains and rules, letting
        # the *last* occurrence take precendence since it could have a
        # non-zero [packet:byte] count we want to preserve.  We also filter
        # out anything in the "remove" list.
        new_filter.reverse()
        new_filter = [line for line in new_filter
                      if _weed_out_duplicate_chains(line) and
                      _weed_out_duplicate_rules(line) and
                      _weed_out_removes(line)]
        new_filter.reverse()

        # flush lists, just in case we didn't find something
        remove_chains.clear()
        for rule in remove_rules:
            remove_rules.remove(rule)

        return new_filter

    def _get_traffic_counters_cmd_tables(self, chain, wrap=True):
        name = self.get_chain_name(chain, wrap, self.prefix_chain)

        cmd_tables = [('ebtables', key) for key, table in self.tables.items()
                      if name in table._select_chain_set(wrap)]

        return cmd_tables

    def get_traffic_counters(self, chain, wrap=True, zero=False):
        """Return the sum of the traffic counters of all rules of a chain."""
        cmd_tables = self._get_traffic_counters_cmd_tables(chain, wrap)
        if not cmd_tables:
            LOG.warn(_('Attempted to get traffic counters of chain %s which '
                       'does not exist'), chain)
            return

        name = self.get_chain_name(chain, wrap, self.prefix_chain)
        if wrap:
            name = '%s-%s' % (self.prefix_chain, name)
        acc = {'pkts': 0, 'bytes': 0}

        for cmd, table in cmd_tables:
            args = [cmd, '-t', table, '-L', name, '--Lc']
            if zero:
                args.append('-Z')
            if self.namespace:
                args = ['ip', 'netns', 'exec', self.namespace] + args
            current_table = (self.execute(args,
                             root_helper=self.root_helper))
            current_lines = current_table.split('\n')

            for line in current_lines[3:]:
                if not line:
                    break
                data = line.split()
                if (len(data) < 7 or
                        not data[-1].isdigit() or
                        not data[-5].isdigit()):
                    break

                acc['pkts'] += int(data[-5])
                acc['bytes'] += int(data[-1])

        return acc


class EbtablesManagerTransaction(object):
    __transactions = {}

    def __init__(self, ebtables_manager):
        self.ebtables_manager = ebtables_manager

        transaction = self.__transactions.get(ebtables_manager, 0)
        transaction += 1
        self.__transactions[ebtables_manager] = transaction

    def __enter__(self):
        return self.ebtables_manager

    def __exit__(self, type, value, traceback):
        transaction = self.__transactions.get(self.ebtables_manager)
        if transaction == 1:
            self.ebtables_manager.apply()
            del self.__transactions[self.ebtables_manager]
        else:
            transaction -= 1
            self.__transactions[self.ebtables_manager] = transaction
