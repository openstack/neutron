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

"""
Implement a manager for ebtables rules.

NOTE: The ebtables manager contains a lot of duplicated or very similar code
      from the iptables manager. An option would have been to refactor the
      iptables manager so that ebtables and iptables manager can share common
      code. However, the iptables manager was considered too brittle and
      in need for a larger re-work or full replacement in the future.
      Therefore, it was decided not to do any refactoring for now and to accept
      the code duplication.

"""

import inspect
import os

from oslo_log import log as logging

from neutron.i18n import _LW


LOG = logging.getLogger(__name__)


MAX_CHAIN_LEN_EBTABLES = 31
# NOTE(jbrendel): ebtables supports chain names of up to 31 characters, and
#                 we add up to 12 characters to prefix_chain which is used
#                 as a prefix, so we limit it to 19 characters.
POSTROUTING_STR = '-POSTROUTING'
MAX_LEN_PREFIX_CHAIN = MAX_CHAIN_LEN_EBTABLES - len(POSTROUTING_STR)

# When stripping or calculating string lengths, sometimes a '-' which separates
# name components needs to be considered.
DASH_STR_LEN = 1


def binary_name():
    """Grab the name of the binary we're running in."""
    return os.path.basename(inspect.stack()[-1][1])


def _get_prefix_chain(prefix_chain=None):
    """Determine the prefix chain."""
    if prefix_chain:
        return prefix_chain[:MAX_LEN_PREFIX_CHAIN]
    else:
        return binary_name()[:MAX_LEN_PREFIX_CHAIN]


def get_chain_name(chain_name, wrap=True, prefix_chain=None):
    """Determine the chain name."""
    if wrap:
        # Get the possible chain name length in function of the prefix name
        # length.
        chain_len = (MAX_CHAIN_LEN_EBTABLES -
                     (len(_get_prefix_chain(prefix_chain)) + DASH_STR_LEN))
        return chain_name[:chain_len]
    else:
        return chain_name[:MAX_CHAIN_LEN_EBTABLES]


class EbtablesRule(object):
    """An ebtables rule.

    You shouldn't need to use this class directly, it's only used by
    EbtablesManager.

    """

    def __init__(self, chain, rule, wrap=True, top=False,
                 prefix_chain=None):
        self.prefix_chain = _get_prefix_chain(prefix_chain)
        self.chain = get_chain_name(chain, wrap, prefix_chain)
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


class EbtablesTable(object):
    """An ebtables table."""

    def __init__(self, prefix_chain=None):
        self.rules = []
        self.rules_to_remove = []
        self.chains = set()
        self.unwrapped_chains = set()
        self.chains_to_remove = set()
        self.prefix_chain = _get_prefix_chain(prefix_chain)

    def add_chain(self, name, wrap=True):
        """Adds a named chain to the table.

        The chain name is wrapped to be unique for the component creating
        it, so different components of Neutron can safely create identically
        named chains without interfering with one another.

        At the moment, its wrapped name is <prefix chain>-<chain name>,
        so if neutron-server creates a chain named 'OUTPUT', it'll actually
        end up named 'neutron-server-OUTPUT'.

        """
        name = get_chain_name(name, wrap, self.prefix_chain)
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
        self.remove_chain(name, wrap, log_not_found=False)

    def remove_chain(self, name, wrap=True, log_not_found=True):
        """Remove named chain.

        This removal "cascades". All rules in the chain are removed, as are
        all rules in other chains that jump to it.

        If the chain is not found then this is merely logged.

        """
        name = get_chain_name(name, wrap, self.prefix_chain)
        chain_set = self._select_chain_set(wrap)

        if name not in chain_set:
            if log_not_found:
                LOG.warn(_LW('Attempted to remove chain %s '
                             'which does not exist'), name)
            return

        chain_set.remove(name)

        if not wrap:
            # non-wrapped chains and rules need to be dealt with specially,
            # so we keep a list of them to be iterated over in apply()
            self.chains_to_remove.add(name)

            # first, add rules to remove that have a matching chain name
            self.rules_to_remove += [r for r in self.rules if r.chain == name]

        # next, remove rules from list that have a matching chain name
        self.rules = [r for r in self.rules if r.chain != name]

        if not wrap:
            jump_snippet = '-j %s' % name
            # next, add rules to remove that have a matching jump chain
            self.rules_to_remove += [r for r in self.rules
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
        chain = get_chain_name(chain, wrap, self.prefix_chain)
        if wrap and chain not in self.chains:
            raise LookupError(_('Unknown chain: %r') % chain)

        if '$' in rule:
            rule = ' '.join(map(self._wrap_target_chain, rule.split(' ')))

        self.rules.append(EbtablesRule(chain, rule, wrap, top,
                                       self.prefix_chain))

    def remove_rule(self, chain, rule, wrap=True, top=False):
        """Remove a rule from a chain.

        However, if the rule jumps to one of your wrapped chains,
        prepend its name with a '$' which will ensure the wrapping
        is applied correctly.
        """
        chain = get_chain_name(chain, wrap, self.prefix_chain)
        if '$' in rule:
            rule = ' '.join(map(self._wrap_target_chain, rule.split(' ')))

        try:
            self.rules.remove(EbtablesRule(chain, rule, wrap, top,
                                           self.prefix_chain))
            if not wrap:
                self.rules_to_remove.append(
                    EbtablesRule(chain, rule, wrap, top,
                                 self.prefix_chain))
        except ValueError:
            LOG.warn(_LW('Tried to remove rule that was not there:'
                     ' %(chain)r %(rule)r %(wrap)r %(top)r'),
                     {'chain': chain, 'rule': rule,
                      'top': top, 'wrap': wrap})

    def _wrap_target_chain(self, s):
        if s.startswith('$'):
            return ('%s-%s' % (self.prefix_chain, s[1:]))
        return s

    def empty_chain(self, chain, wrap=True):
        """Remove all rules from a chain."""
        chain = get_chain_name(chain, wrap, self.prefix_chain)
        chained_rules = [rule for rule in self.rules
                         if rule.chain == chain and rule.wrap == wrap]
        for rule in chained_rules:
            self.rules.remove(rule)
