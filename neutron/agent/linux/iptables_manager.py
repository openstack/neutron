# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Locaweb.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @author: Juliano Martinez, Locaweb.
# based on
#   https://github.com/openstack/nova/blob/master/nova/network/linux_net.py

"""Implements iptables rules using linux utilities."""

import inspect
import os

from neutron.agent.linux import utils as linux_utils
from neutron.common import utils
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


# NOTE(vish): Iptables supports chain names of up to 28 characters,  and we
#             add up to 12 characters to binary_name which is used as a prefix,
#             so we limit it to 16 characters.
#             (max_chain_name_length - len('-POSTROUTING') == 16)
def get_binary_name():
    """Grab the name of the binary we're running in."""
    return os.path.basename(inspect.stack()[-1][1])[:16]

binary_name = get_binary_name()

# A length of a chain name must be less than or equal to 11 characters.
# <max length of iptables chain name> - (<binary_name> + '-') = 28-(16+1) = 11
MAX_CHAIN_LEN_WRAP = 11
MAX_CHAIN_LEN_NOWRAP = 28


def get_chain_name(chain_name, wrap=True):
    if wrap:
        return chain_name[:MAX_CHAIN_LEN_WRAP]
    else:
        return chain_name[:MAX_CHAIN_LEN_NOWRAP]


class IptablesRule(object):
    """An iptables rule.

    You shouldn't need to use this class directly, it's only used by
    IptablesManager.

    """

    def __init__(self, chain, rule, wrap=True, top=False,
                 binary_name=binary_name, tag=None):
        self.chain = get_chain_name(chain, wrap)
        self.rule = rule
        self.wrap = wrap
        self.top = top
        self.wrap_name = binary_name[:16]
        self.tag = tag

    def __eq__(self, other):
        return ((self.chain == other.chain) and
                (self.rule == other.rule) and
                (self.top == other.top) and
                (self.wrap == other.wrap))

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        if self.wrap:
            chain = '%s-%s' % (self.wrap_name, self.chain)
        else:
            chain = self.chain
        return '-A %s %s' % (chain, self.rule)


class IptablesTable(object):
    """An iptables table."""

    def __init__(self, binary_name=binary_name):
        self.rules = []
        self.remove_rules = []
        self.chains = set()
        self.unwrapped_chains = set()
        self.remove_chains = set()
        self.wrap_name = binary_name[:16]

    def add_chain(self, name, wrap=True):
        """Adds a named chain to the table.

        The chain name is wrapped to be unique for the component creating
        it, so different components of Nova can safely create identically
        named chains without interfering with one another.

        At the moment, its wrapped name is <binary name>-<chain name>,
        so if nova-compute creates a chain named 'OUTPUT', it'll actually
        end up named 'nova-compute-OUTPUT'.

        """
        name = get_chain_name(name, wrap)
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
        name = get_chain_name(name, wrap)
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
        name = get_chain_name(name, wrap)
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
            jump_snippet = '-j %s-%s' % (self.wrap_name, name)

        # finally, remove rules from list that have a matching jump chain
        self.rules = [r for r in self.rules
                      if jump_snippet not in r.rule]

    def add_rule(self, chain, rule, wrap=True, top=False, tag=None):
        """Add a rule to the table.

        This is just like what you'd feed to iptables, just without
        the '-A <chain name>' bit at the start.

        However, if you need to jump to one of your wrapped chains,
        prepend its name with a '$' which will ensure the wrapping
        is applied correctly.

        """
        chain = get_chain_name(chain, wrap)
        if wrap and chain not in self.chains:
            raise LookupError(_('Unknown chain: %r') % chain)

        if '$' in rule:
            rule = ' '.join(
                self._wrap_target_chain(e, wrap) for e in rule.split(' '))

        self.rules.append(IptablesRule(chain, rule, wrap, top, self.wrap_name,
                                       tag))

    def _wrap_target_chain(self, s, wrap):
        if s.startswith('$'):
            s = ('%s-%s' % (self.wrap_name, get_chain_name(s[1:], wrap)))

        return s

    def remove_rule(self, chain, rule, wrap=True, top=False):
        """Remove a rule from a chain.

        Note: The rule must be exactly identical to the one that was added.
        You cannot switch arguments around like you can with the iptables
        CLI tool.

        """
        chain = get_chain_name(chain, wrap)
        try:
            if '$' in rule:
                rule = ' '.join(
                    self._wrap_target_chain(e, wrap) for e in rule.split(' '))

            self.rules.remove(IptablesRule(chain, rule, wrap, top,
                                           self.wrap_name))
            if not wrap:
                self.remove_rules.append(IptablesRule(chain, rule, wrap, top,
                                                      self.wrap_name))
        except ValueError:
            LOG.warn(_('Tried to remove rule that was not there:'
                       ' %(chain)r %(rule)r %(wrap)r %(top)r'),
                     {'chain': chain, 'rule': rule,
                      'top': top, 'wrap': wrap})

    def empty_chain(self, chain, wrap=True):
        """Remove all rules from a chain."""
        chain = get_chain_name(chain, wrap)
        chained_rules = [rule for rule in self.rules
                         if rule.chain == chain and rule.wrap == wrap]
        for rule in chained_rules:
            self.rules.remove(rule)

    def clear_rules_by_tag(self, tag):
        if not tag:
            return
        rules = [rule for rule in self.rules if rule.tag == tag]
        for rule in rules:
            self.rules.remove(rule)


class IptablesManager(object):
    """Wrapper for iptables.

    See IptablesTable for some usage docs

    A number of chains are set up to begin with.

    First, neutron-filter-top. It's added at the top of FORWARD and OUTPUT. Its
    name is not wrapped, so it's shared between the various nova workers. It's
    intended for rules that need to live at the top of the FORWARD and OUTPUT
    chains. It's in both the ipv4 and ipv6 set of tables.

    For ipv4 and ipv6, the built-in INPUT, OUTPUT, and FORWARD filter chains
    are wrapped, meaning that the "real" INPUT chain has a rule that jumps to
    the wrapped INPUT chain, etc. Additionally, there's a wrapped chain named
    "local" which is jumped to from neutron-filter-top.

    For ipv4, the built-in PREROUTING, OUTPUT, and POSTROUTING nat chains are
    wrapped in the same was as the built-in filter chains. Additionally,
    there's a snat chain that is applied after the POSTROUTING chain.

    """

    def __init__(self, _execute=None, state_less=False,
                 root_helper=None, use_ipv6=False, namespace=None,
                 binary_name=binary_name):
        if _execute:
            self.execute = _execute
        else:
            self.execute = linux_utils.execute

        self.use_ipv6 = use_ipv6
        self.root_helper = root_helper
        self.namespace = namespace
        self.iptables_apply_deferred = False
        self.wrap_name = binary_name[:16]

        self.ipv4 = {'filter': IptablesTable(binary_name=self.wrap_name)}
        self.ipv6 = {'filter': IptablesTable(binary_name=self.wrap_name)}

        # Add a neutron-filter-top chain. It's intended to be shared
        # among the various nova components. It sits at the very top
        # of FORWARD and OUTPUT.
        for tables in [self.ipv4, self.ipv6]:
            tables['filter'].add_chain('neutron-filter-top', wrap=False)
            tables['filter'].add_rule('FORWARD', '-j neutron-filter-top',
                                      wrap=False, top=True)
            tables['filter'].add_rule('OUTPUT', '-j neutron-filter-top',
                                      wrap=False, top=True)

            tables['filter'].add_chain('local')
            tables['filter'].add_rule('neutron-filter-top', '-j $local',
                                      wrap=False)

        # Wrap the built-in chains
        builtin_chains = {4: {'filter': ['INPUT', 'OUTPUT', 'FORWARD']},
                          6: {'filter': ['INPUT', 'OUTPUT', 'FORWARD']}}

        if not state_less:
            self.ipv4.update(
                {'nat': IptablesTable(binary_name=self.wrap_name)})
            builtin_chains[4].update({'nat': ['PREROUTING',
                                      'OUTPUT', 'POSTROUTING']})

        for ip_version in builtin_chains:
            if ip_version == 4:
                tables = self.ipv4
            elif ip_version == 6:
                tables = self.ipv6

            for table, chains in builtin_chains[ip_version].iteritems():
                for chain in chains:
                    tables[table].add_chain(chain)
                    tables[table].add_rule(chain, '-j $%s' %
                                           (chain), wrap=False)

        if not state_less:
            # Add a neutron-postrouting-bottom chain. It's intended to be
            # shared among the various nova components. We set it as the last
            # chain of POSTROUTING chain.
            self.ipv4['nat'].add_chain('neutron-postrouting-bottom',
                                       wrap=False)
            self.ipv4['nat'].add_rule('POSTROUTING',
                                      '-j neutron-postrouting-bottom',
                                      wrap=False)

            # We add a snat chain to the shared neutron-postrouting-bottom
            # chain so that it's applied last.
            self.ipv4['nat'].add_chain('snat')
            self.ipv4['nat'].add_rule('neutron-postrouting-bottom',
                                      '-j $snat', wrap=False)

            # And then we add a float-snat chain and jump to first thing in
            # the snat chain.
            self.ipv4['nat'].add_chain('float-snat')
            self.ipv4['nat'].add_rule('snat', '-j $float-snat')

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
        lock_name = 'iptables'
        if self.namespace:
            lock_name += '-' + self.namespace

        try:
            with lockutils.lock(lock_name, utils.SYNCHRONIZED_PREFIX, True):
                LOG.debug(_('Got semaphore / lock "%s"'), lock_name)
                return self._apply_synchronized()
        finally:
            LOG.debug(_('Semaphore / lock released "%s"'), lock_name)

    def _apply_synchronized(self):
        """Apply the current in-memory set of iptables rules.

        This will blow away any rules left over from previous runs of the
        same component of Nova, and replace them with our current set of
        rules. This happens atomically, thanks to iptables-restore.

        """
        s = [('iptables', self.ipv4)]
        if self.use_ipv6:
            s += [('ip6tables', self.ipv6)]

        for cmd, tables in s:
            args = ['%s-save' % (cmd,), '-c']
            if self.namespace:
                args = ['ip', 'netns', 'exec', self.namespace] + args
            all_tables = self.execute(args, root_helper=self.root_helper)
            all_lines = all_tables.split('\n')
            for table_name, table in tables.iteritems():
                start, end = self._find_table(all_lines, table_name)
                all_lines[start:end] = self._modify_rules(
                    all_lines[start:end], table, table_name)

            args = ['%s-restore' % (cmd,), '-c']
            if self.namespace:
                args = ['ip', 'netns', 'exec', self.namespace] + args
            self.execute(args, process_input='\n'.join(all_lines),
                         root_helper=self.root_helper)
        LOG.debug(_("IPTablesManager.apply completed with success"))

    def _find_table(self, lines, table_name):
        if len(lines) < 3:
            # length only <2 when fake iptables
            return (0, 0)
        try:
            start = lines.index('*%s' % table_name) - 1
        except ValueError:
            # Couldn't find table_name
            LOG.debug(_('Unable to find table %s'), table_name)
            return (0, 0)
        end = lines[start:].index('COMMIT') + start + 2
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

    def _find_last_entry(self, filter_list, match_str):
        # find a matching entry, starting from the bottom
        for s in reversed(filter_list):
            s = s.strip()
            if match_str in s:
                return s

    def _modify_rules(self, current_lines, table, table_name):
        unwrapped_chains = table.unwrapped_chains
        chains = table.chains
        remove_chains = table.remove_chains
        rules = table.rules
        remove_rules = table.remove_rules

        if not current_lines:
            fake_table = ['# Generated by iptables_manager',
                          '*' + table_name, 'COMMIT',
                          '# Completed by iptables_manager']
            current_lines = fake_table

        # Fill old_filter with any chains or rules we might have added,
        # they could have a [packet:byte] count we want to preserve.
        # Fill new_filter with any chains or rules without our name in them.
        old_filter, new_filter = [], []
        for line in current_lines:
            (old_filter if self.wrap_name in line else
             new_filter).append(line.strip())

        rules_index = self._find_rules_index(new_filter)

        all_chains = [':%s' % name for name in unwrapped_chains]
        all_chains += [':%s-%s' % (self.wrap_name, name) for name in chains]

        # Iterate through all the chains, trying to find an existing
        # match.
        our_chains = []
        for chain in all_chains:
            chain_str = str(chain).strip()

            old = self._find_last_entry(old_filter, chain_str)
            if not old:
                dup = self._find_last_entry(new_filter, chain_str)
            new_filter = [s for s in new_filter if chain_str not in s.strip()]

            # if no old or duplicates, use original chain
            if old or dup:
                chain_str = str(old or dup)
            else:
                # add-on the [packet:bytes]
                chain_str += ' - [0:0]'

            our_chains += [chain_str]

        # Iterate through all the rules, trying to find an existing
        # match.
        our_rules = []
        bot_rules = []
        for rule in rules:
            rule_str = str(rule).strip()
            # Further down, we weed out duplicates from the bottom of the
            # list, so here we remove the dupes ahead of time.

            old = self._find_last_entry(old_filter, rule_str)
            if not old:
                dup = self._find_last_entry(new_filter, rule_str)
            new_filter = [s for s in new_filter if rule_str not in s.strip()]

            # if no old or duplicates, use original rule
            if old or dup:
                rule_str = str(old or dup)
                # backup one index so we write the array correctly
                if not old:
                    rules_index -= 1
            else:
                # add-on the [packet:bytes]
                rule_str = '[0:0] ' + rule_str

            if rule.top:
                # rule.top == True means we want this rule to be at the top.
                our_rules += [rule_str]
            else:
                bot_rules += [rule_str]

        our_rules += bot_rules

        new_filter[rules_index:rules_index] = our_rules
        new_filter[rules_index:rules_index] = our_chains

        def _strip_packets_bytes(line):
            # strip any [packet:byte] counts at start or end of lines
            if line.startswith(':'):
                # it's a chain, for example, ":neutron-billing - [0:0]"
                line = line.split(':')[1]
                line = line.split(' - [', 1)[0]
            elif line.startswith('['):
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

        # We filter duplicates.  Go through the chains and rules, letting
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
        name = get_chain_name(chain, wrap)

        cmd_tables = [('iptables', key) for key, table in self.ipv4.items()
                      if name in table._select_chain_set(wrap)]

        if self.use_ipv6:
            cmd_tables += [('ip6tables', key)
                           for key, table in self.ipv6.items()
                           if name in table._select_chain_set(wrap)]

        return cmd_tables

    def get_traffic_counters(self, chain, wrap=True, zero=False):
        """Return the sum of the traffic counters of all rules of a chain."""
        cmd_tables = self._get_traffic_counters_cmd_tables(chain, wrap)
        if not cmd_tables:
            LOG.warn(_('Attempted to get traffic counters of chain %s which '
                       'does not exist'), chain)
            return

        name = get_chain_name(chain, wrap)
        acc = {'pkts': 0, 'bytes': 0}

        for cmd, table in cmd_tables:
            args = [cmd, '-t', table, '-L', name, '-n', '-v', '-x']
            if zero:
                args.append('-Z')
            if self.namespace:
                args = ['ip', 'netns', 'exec', self.namespace] + args
            current_table = (self.execute(args,
                             root_helper=self.root_helper))
            current_lines = current_table.split('\n')

            for line in current_lines[2:]:
                if not line:
                    break
                data = line.split()
                if (len(data) < 2 or
                        not data[0].isdigit() or
                        not data[1].isdigit()):
                    break

                acc['pkts'] += int(data[0])
                acc['bytes'] += int(data[1])

        return acc
