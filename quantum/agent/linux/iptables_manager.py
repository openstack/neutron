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

from quantum.agent.linux import utils
from quantum.openstack.common import lockutils
from quantum.openstack.common import log as logging

LOG = logging.getLogger(__name__)
# NOTE(vish): Iptables supports chain names of up to 28 characters,  and we
#             add up to 12 characters to binary_name which is used as a prefix,
#             so we limit it to 16 characters.
#             (max_chain_name_length - len('-POSTROUTING') == 16)
binary_name = os.path.basename(inspect.stack()[-1][1])[:16]
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

    def __init__(self, chain, rule, wrap=True, top=False):
        self.chain = get_chain_name(chain, wrap)
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
            chain = '%s-%s' % (binary_name, self.chain)
        else:
            chain = self.chain
        return '-A %s %s' % (chain, self.rule)


class IptablesTable(object):
    """An iptables table."""

    def __init__(self):
        self.rules = []
        self.chains = set()
        self.unwrapped_chains = set()

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
        self.rules = filter(lambda r: r.chain != name, self.rules)
        if wrap:
            jump_snippet = '-j %s-%s' % (binary_name, name)
        else:
            jump_snippet = '-j %s' % (name,)

        self.rules = filter(lambda r: jump_snippet not in r.rule, self.rules)

    def add_rule(self, chain, rule, wrap=True, top=False):
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
            rule = ' '.join(map(self._wrap_target_chain, rule.split(' ')))

        self.rules.append(IptablesRule(chain, rule, wrap, top))

    def _wrap_target_chain(self, s):
        if s.startswith('$'):
            return ('%s-%s' % (binary_name, s[1:]))
        return s

    def remove_rule(self, chain, rule, wrap=True, top=False):
        """Remove a rule from a chain.

        Note: The rule must be exactly identical to the one that was added.
        You cannot switch arguments around like you can with the iptables
        CLI tool.

        """
        chain = get_chain_name(chain, wrap)
        try:
            self.rules.remove(IptablesRule(chain, rule, wrap, top))
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


class IptablesManager(object):
    """Wrapper for iptables.

    See IptablesTable for some usage docs

    A number of chains are set up to begin with.

    First, quantum-filter-top. It's added at the top of FORWARD and OUTPUT. Its
    name is not wrapped, so it's shared between the various nova workers. It's
    intended for rules that need to live at the top of the FORWARD and OUTPUT
    chains. It's in both the ipv4 and ipv6 set of tables.

    For ipv4 and ipv6, the built-in INPUT, OUTPUT, and FORWARD filter chains
    are wrapped, meaning that the "real" INPUT chain has a rule that jumps to
    the wrapped INPUT chain, etc. Additionally, there's a wrapped chain named
    "local" which is jumped to from quantum-filter-top.

    For ipv4, the built-in PREROUTING, OUTPUT, and POSTROUTING nat chains are
    wrapped in the same was as the built-in filter chains. Additionally,
    there's a snat chain that is applied after the POSTROUTING chain.

    """

    def __init__(self, _execute=None, state_less=False,
                 root_helper=None, use_ipv6=False, namespace=None):
        if _execute:
            self.execute = _execute
        else:
            self.execute = utils.execute

        self.use_ipv6 = use_ipv6
        self.root_helper = root_helper
        self.namespace = namespace
        self.iptables_apply_deferred = False

        self.ipv4 = {'filter': IptablesTable()}
        self.ipv6 = {'filter': IptablesTable()}

        # Add a quantum-filter-top chain. It's intended to be shared
        # among the various nova components. It sits at the very top
        # of FORWARD and OUTPUT.
        for tables in [self.ipv4, self.ipv6]:
            tables['filter'].add_chain('quantum-filter-top', wrap=False)
            tables['filter'].add_rule('FORWARD', '-j quantum-filter-top',
                                      wrap=False, top=True)
            tables['filter'].add_rule('OUTPUT', '-j quantum-filter-top',
                                      wrap=False, top=True)

            tables['filter'].add_chain('local')
            tables['filter'].add_rule('quantum-filter-top', '-j $local',
                                      wrap=False)

        # Wrap the built-in chains
        builtin_chains = {4: {'filter': ['INPUT', 'OUTPUT', 'FORWARD']},
                          6: {'filter': ['INPUT', 'OUTPUT', 'FORWARD']}}

        if not state_less:
            self.ipv4.update({'nat': IptablesTable()})
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
            # Add a quantum-postrouting-bottom chain. It's intended to be
            # shared among the various nova components. We set it as the last
            # chain of POSTROUTING chain.
            self.ipv4['nat'].add_chain('quantum-postrouting-bottom',
                                       wrap=False)
            self.ipv4['nat'].add_rule('POSTROUTING',
                                      '-j quantum-postrouting-bottom',
                                      wrap=False)

            # We add a snat chain to the shared quantum-postrouting-bottom
            # chain so that it's applied last.
            self.ipv4['nat'].add_chain('snat')
            self.ipv4['nat'].add_rule('quantum-postrouting-bottom',
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

    @lockutils.synchronized('iptables', 'quantum-', external=True)
    def _apply(self):
        """Apply the current in-memory set of iptables rules.

        This will blow away any rules left over from previous runs of the
        same component of Nova, and replace them with our current set of
        rules. This happens atomically, thanks to iptables-restore.

        """
        s = [('iptables', self.ipv4)]
        if self.use_ipv6:
            s += [('ip6tables', self.ipv6)]

        for cmd, tables in s:
            for table in tables:
                args = ['%s-save' % cmd, '-t', table]
                if self.namespace:
                    args = ['ip', 'netns', 'exec', self.namespace] + args
                current_table = (self.execute(args,
                                 root_helper=self.root_helper))
                current_lines = current_table.split('\n')
                new_filter = self._modify_rules(current_lines,
                                                tables[table])
                args = ['%s-restore' % (cmd)]
                if self.namespace:
                    args = ['ip', 'netns', 'exec', self.namespace] + args
                self.execute(args,
                             process_input='\n'.join(new_filter),
                             root_helper=self.root_helper)
        LOG.debug(_("IPTablesManager.apply completed with success"))

    def _modify_rules(self, current_lines, table, binary=None):
        unwrapped_chains = table.unwrapped_chains
        chains = table.chains
        rules = table.rules

        # Remove any trace of our rules
        new_filter = filter(lambda line: binary_name
                            not in line, current_lines)

        seen_chains = False
        rules_index = 0
        for rules_index, rule in enumerate(new_filter):
            if not seen_chains:
                if rule.startswith(':'):
                    seen_chains = True
            else:
                if not rule.startswith(':'):
                    break

        our_rules = []
        for rule in rules:
            rule_str = str(rule)
            if rule.top:
                # rule.top == True means we want this rule to be at the top.
                # Further down, we weed out duplicates from the bottom of the
                # list, so here we remove the dupes ahead of time.
                new_filter = filter(lambda s: s.strip() != rule_str.strip(),
                                    new_filter)
            our_rules += [rule_str]

        new_filter[rules_index:rules_index] = our_rules

        new_filter[rules_index:rules_index] = [':%s - [0:0]' % (name)
                                               for name in unwrapped_chains]
        new_filter[rules_index:rules_index] = [':%s-%s - [0:0]' %
                                               (binary_name, name)
                                               for name in chains]

        seen_lines = set()

        def _weed_out_duplicates(line):
            line = line.strip()
            if line in seen_lines:
                return False
            else:
                seen_lines.add(line)
                return True

        # We filter duplicates, letting the *last* occurrence take
        # precedence.
        new_filter.reverse()
        new_filter = filter(_weed_out_duplicates, new_filter)
        new_filter.reverse()
        return new_filter
