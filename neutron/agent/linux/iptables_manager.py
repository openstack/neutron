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
# based on
# https://github.com/openstack/nova/blob/master/nova/network/linux_net.py

"""Implements iptables rules using linux utilities."""

import collections
import contextlib
import difflib
import os
import re
import sys

from neutron_lib import constants
from neutron_lib import exceptions
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.utils import runtime
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron._i18n import _
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_comments as ic
from neutron.agent.linux import utils as linux_utils
from neutron.common import _constants as n_const
from neutron.common import utils
from neutron.conf.agent import common as config

LOG = logging.getLogger(__name__)

config.register_iptables_opts(cfg.CONF)


# NOTE(vish): Iptables supports chain names of up to 28 characters,  and we
#             add up to 12 characters to binary_name which is used as a prefix,
#             so we limit it to 16 characters.
#             (max_chain_name_length - len('-POSTROUTING') == 16)
def get_binary_name():
    """Grab the name of the binary we're running in."""
    return os.path.basename(sys.argv[0])[:16].replace(' ', '_')


binary_name = get_binary_name()

# Number of iptables rules to print before and after a rule that causes a
# a failure during iptables-restore
IPTABLES_ERROR_LINES_OF_CONTEXT = 5

# RESOURCE_PROBLEM in include/xtables.h
XTABLES_RESOURCE_PROBLEM_CODE = 4

# xlock wait interval, in microseconds
XLOCK_WAIT_INTERVAL = 200000


def comment_rule(rule, comment):
    if not cfg.CONF.AGENT.comment_iptables_rules or not comment:
        return rule
    # iptables-save outputs the comment before the jump so we need to match
    # that order so _find_last_entry works
    comment = '-m comment --comment "%s"' % comment
    if rule.startswith('-j'):
        # this is a jump only rule so we just put the comment first
        return '%s %s' % (comment, rule)
    try:
        jpos = rule.index(' -j ')
        return ' '.join((rule[:jpos], comment, rule[jpos + 1:]))
    except ValueError:
        return '%s %s' % (rule, comment)


def get_chain_name(chain_name, wrap=True):
    if wrap:
        return chain_name[:constants.MAX_IPTABLES_CHAIN_LEN_WRAP]
    else:
        return chain_name[:constants.MAX_IPTABLES_CHAIN_LEN_NOWRAP]


class IptablesRule(object):
    """An iptables rule.

    You shouldn't need to use this class directly, it's only used by
    IptablesManager.

    """

    def __init__(self, chain, rule, wrap=True, top=False,
                 binary_name=binary_name, tag=None, comment=None):
        self.chain = get_chain_name(chain, wrap)
        self.rule = rule
        self.wrap = wrap
        self.top = top
        self.wrap_name = binary_name[:16]
        self.tag = tag
        self.comment = comment

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
        rule = '-A %s %s' % (chain, self.rule)
        # If self.rule is '' the above will cause a trailing space, which
        # could cause us to not match on save/restore, so strip it now.
        return comment_rule(rule.strip(), self.comment)


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
        so if neutron-openvswitch-agent creates a chain named 'OUTPUT',
        it'll actually end up being named 'neutron-openvswi-OUTPUT'.

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

    def remove_chain(self, name, wrap=True):
        """Remove named chain.

        This removal "cascades". All rule in the chain are removed, as are
        all rules in other chains that jump to it.

        If the chain is not found, this is merely logged.

        """
        name = get_chain_name(name, wrap)
        chain_set = self._select_chain_set(wrap)

        if name not in chain_set:
            LOG.debug('Attempted to remove chain %s which does not exist',
                      name)
            return

        chain_set.remove(name)

        if not wrap:
            # non-wrapped chains and rules need to be dealt with specially,
            # so we keep a list of them to be iterated over in apply()
            self.remove_chains.add(name)

            # Add rules to remove that have a matching chain name or
            # a matching jump chain
            jump_snippet = '-j %s' % name
            self.remove_rules += [str(r) for r in self.rules
                                  if r.chain == name or jump_snippet in r.rule]
        else:
            jump_snippet = '-j %s-%s' % (self.wrap_name, name)

        # Remove rules from list that have a matching chain name or
        # a matching jump chain
        self.rules = [r for r in self.rules
                      if r.chain != name and jump_snippet not in r.rule]

    def add_rule(self, chain, rule, wrap=True, top=False, tag=None,
                 comment=None):
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
                                       tag, comment))

    def _wrap_target_chain(self, s, wrap):
        if s.startswith('$'):
            s = ('%s-%s' % (self.wrap_name, get_chain_name(s[1:], wrap)))

        return s

    def remove_rule(self, chain, rule, wrap=True, top=False, comment=None):
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
                                           self.wrap_name,
                                           comment=comment))
            if not wrap:
                self.remove_rules.append(str(IptablesRule(chain, rule, wrap,
                                                          top, self.wrap_name,
                                                          comment=comment)))
        except ValueError:
            LOG.warning('Tried to remove rule that was not there:'
                        ' %(chain)r %(rule)r %(wrap)r %(top)r',
                        {'chain': chain, 'rule': rule,
                         'top': top, 'wrap': wrap})

    def _get_chain_rules(self, chain, wrap):
        chain = get_chain_name(chain, wrap)
        return [rule for rule in self.rules
                if rule.chain == chain and rule.wrap == wrap]

    def empty_chain(self, chain, wrap=True):
        """Remove all rules from a chain."""
        chained_rules = self._get_chain_rules(chain, wrap)
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

    First, neutron-filter-top. It's added at the top of FORWARD and OUTPUT.
    Its name is not wrapped, so it's shared between the various neutron
    workers. It's intended for rules that need to live at the top of the
    FORWARD and OUTPUT chains. It's in both the ipv4 and ipv6 set of tables.

    For ipv4 and ipv6, the built-in INPUT, OUTPUT, and FORWARD filter chains
    are wrapped, meaning that the "real" INPUT chain has a rule that jumps to
    the wrapped INPUT chain, etc. Additionally, there's a wrapped chain named
    "local" which is jumped to from neutron-filter-top.

    For ipv4, the built-in PREROUTING, OUTPUT, and POSTROUTING nat chains are
    wrapped in the same was as the built-in filter chains. Additionally,
    there's a snat chain that is applied after the POSTROUTING chain.

    """

    # Flag to denote we've already tried and used -w successfully, so don't
    # run iptables-restore without it.
    use_table_lock = False

    # Flag to denote iptables --random-fully option enabled
    _random_fully = None

    def __init__(self, state_less=False, use_ipv6=False, nat=True,
                 namespace=None, binary_name=binary_name, external_lock=True):
        self.use_ipv6 = use_ipv6
        self.namespace = namespace
        self.iptables_apply_deferred = False
        self.wrap_name = binary_name[:16]
        self.external_lock = external_lock

        self.ipv4 = {'filter': IptablesTable(binary_name=self.wrap_name)}
        self.ipv6 = {'filter': IptablesTable(binary_name=self.wrap_name)}

        # Add a neutron-filter-top chain. It's intended to be shared
        # among the various neutron components. It sits at the very top
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

        self.ipv4.update({'raw': IptablesTable(binary_name=self.wrap_name)})
        self.ipv6.update({'raw': IptablesTable(binary_name=self.wrap_name)})

        self.ipv4.update({'nat': IptablesTable(binary_name=self.wrap_name)})
        self.ipv6.update({'nat': IptablesTable(binary_name=self.wrap_name)})

        # Wrap the built-in chains
        builtin_chains = {4: {'filter': ['INPUT', 'OUTPUT', 'FORWARD']},
                          6: {'filter': ['INPUT', 'OUTPUT', 'FORWARD']}}
        builtin_chains[4].update({'raw': ['PREROUTING', 'OUTPUT']})
        builtin_chains[6].update({'raw': ['PREROUTING', 'OUTPUT']})
        builtin_chains[4].update({'nat': ['PREROUTING']})
        builtin_chains[6].update({'nat': ['PREROUTING']})
        self._configure_builtin_chains(builtin_chains)

        if not state_less:
            self.initialize_mangle_table()
            if nat:
                self.initialize_nat_table()

    def initialize_mangle_table(self):
        self.ipv4.update(
            {'mangle': IptablesTable(binary_name=self.wrap_name)})
        self.ipv6.update(
            {'mangle': IptablesTable(binary_name=self.wrap_name)})

        builtin_chains = {
            4: {'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT',
                           'POSTROUTING']},
            6: {'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT',
                           'POSTROUTING']}}
        self._configure_builtin_chains(builtin_chains)

        # Add a mark chain to mangle PREROUTING chain. It is used to
        # identify ingress packets from a certain interface.
        self.ipv4['mangle'].add_chain('mark')
        self.ipv4['mangle'].add_rule('PREROUTING', '-j $mark')

    def initialize_nat_table(self):
        self.ipv4.update(
            {'nat': IptablesTable(binary_name=self.wrap_name)})
        self.ipv6.update(
            {'nat': IptablesTable(binary_name=self.wrap_name)})

        builtin_chains = {
            4: {'nat': ['PREROUTING', 'OUTPUT', 'POSTROUTING']},
            6: {'nat': ['PREROUTING']}}
        self._configure_builtin_chains(builtin_chains)

        # Add a neutron-postrouting-bottom chain. It's intended to be
        # shared among the various neutron components. We set it as the
        # last chain of POSTROUTING chain.
        self.ipv4['nat'].add_chain('neutron-postrouting-bottom', wrap=False)
        self.ipv4['nat'].add_rule(
            'POSTROUTING', '-j neutron-postrouting-bottom', wrap=False)

        # We add a snat chain to the shared neutron-postrouting-bottom
        # chain so that it's applied last.
        self.ipv4['nat'].add_chain('snat')
        self.ipv4['nat'].add_rule('neutron-postrouting-bottom',
                                  '-j $snat', wrap=False,
                                  comment=ic.SNAT_OUT)

        # And then we add a float-snat chain and jump to first thing in
        # the snat chain.
        self.ipv4['nat'].add_chain('float-snat')
        self.ipv4['nat'].add_rule('snat', '-j $float-snat')

    def _configure_builtin_chains(self, builtin_chains):
        for ip_version in builtin_chains:
            if ip_version == 4:
                tables = self.ipv4
            elif ip_version == 6:
                tables = self.ipv6

            for table, chains in builtin_chains[ip_version].items():
                for chain in chains:
                    tables[table].add_chain(chain)
                    tables[table].add_rule(chain, '-j $%s' %
                                           (chain), wrap=False)

    def get_tables(self, ip_version):
        return {4: self.ipv4, 6: self.ipv6}[ip_version]

    def get_chain(self, table, chain, ip_version=4, wrap=True):
        try:
            requested_table = self.get_tables(ip_version)[table]
        except KeyError:
            return []
        return requested_table._get_chain_rules(chain, wrap)

    def is_chain_empty(self, table, chain, ip_version=4, wrap=True):
        return not self.get_chain(table, chain, ip_version, wrap)

    @contextlib.contextmanager
    def defer_apply(self):
        """Defer apply context."""
        self.defer_apply_on()
        try:
            yield
        finally:
            try:
                self.defer_apply_off()
            except l3_exc.IpTablesApplyException:
                # already in the format we want, just reraise
                raise
            except Exception:
                msg = _('Failure applying iptables rules')
                LOG.exception(msg)
                raise l3_exc.IpTablesApplyException(msg)

    def defer_apply_on(self):
        self.iptables_apply_deferred = True

    def defer_apply_off(self):
        self.iptables_apply_deferred = False
        self._apply()

    def apply(self):
        if self.iptables_apply_deferred:
            return

        return self._apply()

    def _apply(self):
        lock_name = 'iptables'
        if self.namespace:
            lock_name += '-' + self.namespace

        # NOTE(ihrachys) we may get rid of the lock once all supported
        # platforms get iptables with 999eaa241212d3952ddff39a99d0d55a74e3639e
        # ("iptables-restore: support acquiring the lock.")
        with lockutils.lock(lock_name, runtime.SYNCHRONIZED_PREFIX,
                            external=self.external_lock):
            first = self._apply_synchronized()
            if not cfg.CONF.AGENT.debug_iptables_rules:
                return first
            LOG.debug('List of IPTables Rules applied: %s', '\n'.join(first))
            second = self._apply_synchronized()
            if second:
                msg = (_("IPTables Rules did not converge. Diff: %s") %
                       '\n'.join(second))
                LOG.error(msg)
                raise l3_exc.IpTablesApplyException(msg)
            return first

    def get_rules_for_table(self, table):
        """Runs iptables-save on a table and returns the results."""
        args = ['iptables-save', '-t', table]
        if self.namespace:
            args = ['ip', 'netns', 'exec', self.namespace] + args
        return linux_utils.execute(args, run_as_root=True,
                                   privsep_exec=True).split('\n')

    def _get_version(self):
        # Output example is "iptables v1.6.2"
        args = ['iptables', '--version']
        version = str(linux_utils.execute(
            args, run_as_root=True, privsep_exec=True).split()[1][1:])
        LOG.debug("IPTables version installed: %s", version)
        return version

    @property
    def random_fully(self):
        if self._random_fully is not None:
            return self._random_fully

        version = self._get_version()

        random_fully_support = utils.is_version_greater_equal(
            version, n_const.IPTABLES_RANDOM_FULLY_VERSION)

        self.__class__._random_fully = random_fully_support and \
            cfg.CONF.AGENT.use_random_fully

        return self._random_fully

    @property
    def xlock_wait_time(self):
        # give agent some time to report back to server
        return str(max(int(cfg.CONF.AGENT.report_interval / 3.0), 1))

    def _do_run_restore(self, args, commands, lock=False):
        args = args[:]
        if lock:
            args += ['-w', self.xlock_wait_time, '-W', XLOCK_WAIT_INTERVAL]
        try:
            kwargs = {} if lock else {'log_fail_as_error': False}
            linux_utils.execute(args, process_input='\n'.join(commands),
                                run_as_root=True, privsep_exec=True, **kwargs)
        except RuntimeError as error:
            return error

    def _run_restore(self, args, commands):
        # If we've already tried and used -w successfully, don't
        # run iptables-restore without it.
        if self.use_table_lock:
            return self._do_run_restore(args, commands, lock=True)

        err = self._do_run_restore(args, commands)
        if (isinstance(err, exceptions.ProcessExecutionError) and
                err.returncode == XTABLES_RESOURCE_PROBLEM_CODE):
            # maybe we run on a platform that includes iptables commit
            # 999eaa241212d3952ddff39a99d0d55a74e3639e (for example, latest
            # RHEL) and failed because of xlock acquired by another
            # iptables process running in parallel. Try to use -w to
            # acquire xlock.
            err = self._do_run_restore(args, commands, lock=True)
            if not err:
                self.__class__.use_table_lock = True
        return err

    def _log_restore_err(self, err, commands):
        try:
            line_no = int(re.search(
                'iptables-restore: line ([0-9]+?) failed',
                str(err)).group(1))
            context = IPTABLES_ERROR_LINES_OF_CONTEXT
            log_start = max(0, line_no - context)
            log_end = line_no + context
        except AttributeError:
            # line error wasn't found, print all lines instead
            log_start = 0
            log_end = len(commands)
        log_lines = ('%7d. %s' % (idx, l)
                     for idx, l in enumerate(
                         commands[log_start:log_end],
                         log_start + 1)
                     )
        LOG.error("IPTablesManager.apply failed to apply the "
                  "following set of iptables rules:\n%s",
                  '\n'.join(log_lines))

    def _apply_synchronized(self):
        """Apply the current in-memory set of iptables rules.

        This will create a diff between the rules from the previous runs
        and replace them with the current set of rules.
        This happens atomically, thanks to iptables-restore.

        Returns a list of the changes that were sent to iptables-save.
        """
        s = [('iptables', self.ipv4)]
        if self.use_ipv6:
            s += [('ip6tables', self.ipv6)]
        all_commands = []  # variable to keep track all commands for return val
        for cmd, tables in s:
            args = ['%s-save' % (cmd,)]
            if self.namespace:
                args = ['ip', 'netns', 'exec', self.namespace] + args
            try:
                save_output = linux_utils.execute(args, run_as_root=True,
                                                  privsep_exec=True)
            except RuntimeError:
                # We could be racing with a cron job deleting namespaces.
                # It is useless to try to apply iptables rules over and
                # over again in a endless loop if the namespace does not
                # exist.
                with excutils.save_and_reraise_exception() as ctx:
                    if (self.namespace and not
                            ip_lib.network_namespace_exists(self.namespace)):
                        ctx.reraise = False
                        LOG.error("Namespace %s was deleted during IPTables "
                                  "operations.", self.namespace)
                        return []
            all_lines = save_output.split('\n')
            commands = []
            # Traverse tables in sorted order for predictable dump output
            for table_name in sorted(tables):
                table = tables[table_name]
                # isolate the lines of the table we are modifying
                start, end = self._find_table(all_lines, table_name)
                old_rules = all_lines[start:end]
                # generate the new table state we want
                new_rules = self._modify_rules(old_rules, table, table_name)
                # generate the iptables commands to get between the old state
                # and the new state
                changes = _generate_path_between_rules(old_rules, new_rules)
                if changes:
                    # if there are changes to the table, we put on the header
                    # and footer that iptables-save needs
                    commands += (['# Generated by iptables_manager'] +
                                 ['*%s' % table_name] + changes +
                                 ['COMMIT', '# Completed by iptables_manager'])
            if not commands:
                continue
            all_commands += commands

            # always end with a new line
            commands.append('')

            args = ['%s-restore' % (cmd,), '-n']
            if self.namespace:
                args = ['ip', 'netns', 'exec', self.namespace] + args

            err = self._run_restore(args, commands)
            if err:
                self._log_restore_err(err, commands)
                raise err

        LOG.debug("IPTablesManager.apply completed with success. %d iptables "
                  "commands were issued", len(all_commands))
        return all_commands

    def _find_table(self, lines, table_name):
        if len(lines) < 3:
            # length only <2 when fake iptables
            return (0, 0)
        try:
            start = lines.index('*%s' % table_name)
        except ValueError:
            # Couldn't find table_name
            LOG.debug('Unable to find table %s', table_name)
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
        # Chains are stored as sets to avoid duplicates.
        # Sort the output chains here to make their order predictable.
        unwrapped_chains = sorted(table.unwrapped_chains)
        chains = sorted(table.chains)
        rules = set(map(str, table.rules))

        # we don't want to change any rules that don't belong to us so we start
        # the new_filter with these rules
        # there are some rules that belong to us but they don't have the wrap
        # name. we want to add them in the right location in case our new rules
        # changed the order
        # (e.g. '-A FORWARD -j neutron-filter-top')
        new_filter = [line.strip() for line in current_lines
                      if self.wrap_name not in line and
                      line.strip() not in rules]

        # generate our list of chain names
        our_chains = [':%s-%s' % (self.wrap_name, name) for name in chains]

        # the unwrapped chains (e.g. neutron-filter-top) may already exist in
        # the new_filter since they aren't marked by the wrap_name so we only
        # want to add them if they aren't already there
        our_chains += [':%s' % name for name in unwrapped_chains
                       if not any(':%s' % name in s for s in new_filter)]

        our_top_rules = []
        our_bottom_rules = []
        for rule in table.rules:
            rule_str = str(rule)

            if rule.top:
                # rule.top == True means we want this rule to be at the top.
                our_top_rules += [rule_str]
            else:
                our_bottom_rules += [rule_str]

        our_chains_and_rules = our_chains + our_top_rules + our_bottom_rules

        # locate the position immediately after the existing chains to insert
        # our chains and rules
        rules_index = self._find_rules_index(new_filter)
        new_filter[rules_index:rules_index] = our_chains_and_rules

        def _weed_out_removes(line):
            # remove any rules or chains from the filter that were slated
            # for removal
            if line.startswith(':'):
                chain = line[1:]
                if chain in table.remove_chains:
                    table.remove_chains.remove(chain)
                    return False
            else:
                if line in table.remove_rules:
                    table.remove_rules.remove(line)
                    return False
            # Leave it alone
            return True

        seen_lines = set()

        # TODO(kevinbenton): remove this function and the next one. They are
        # just oversized brooms to sweep bugs under the rug!!! We generate the
        # rules and we shouldn't be generating duplicates.
        def _weed_out_duplicates(line):
            if line in seen_lines:
                thing = 'chain' if line.startswith(':') else 'rule'
                LOG.warning("Duplicate iptables %(thing)s detected. This "
                            "may indicate a bug in the iptables "
                            "%(thing)s generation code. Line: %(line)s",
                            {'thing': thing, 'line': line})
                return False
            seen_lines.add(line)
            # Leave it alone
            return True

        new_filter.reverse()
        new_filter = [line for line in new_filter
                      if _weed_out_duplicates(line) and
                      _weed_out_removes(line)]
        new_filter.reverse()

        # flush lists, just in case a rule or chain marked for removal
        # was already gone. (chains is a set, rules is a list)
        table.remove_chains.clear()
        table.remove_rules = []

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
            LOG.warning('Attempted to get traffic counters of chain %s '
                        'which does not exist', chain)
            return

        name = get_chain_name(chain, wrap)
        acc = {'pkts': 0, 'bytes': 0}

        for cmd, table in cmd_tables:
            args = [cmd, '-t', table, '-L', name, '-n', '-v', '-x',
                    '-w', self.xlock_wait_time]
            if zero:
                args.append('-Z')
            if self.namespace:
                args = ['ip', 'netns', 'exec', self.namespace] + args

            # Execute iptables command in the linux host.
            # When routers migrate from a host,an exception might happen here,
            # and we do not care about it. Therefore, we do not need to log
            # this error in production environments. Only when debug mode is
            # enabled is that we need to log the error. This is used to avoid
            # generating alarms that will be ignored by  operators.
            current_table = linux_utils.execute(
                args, run_as_root=True, privsep_exec=True,
                log_fail_as_error=cfg.CONF.debug)
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


def _generate_path_between_rules(old_rules, new_rules):
    """Generates iptables commands to get from old_rules to new_rules.

    This function diffs the two rule sets and then calculates the iptables
    commands necessary to get from the old rules to the new rules using
    insert and delete commands.
    """
    old_by_chain = _get_rules_by_chain(old_rules)
    new_by_chain = _get_rules_by_chain(new_rules)
    old_chains, new_chains = set(old_by_chain.keys()), set(new_by_chain.keys())
    # all referenced chains should be declared at the top before rules.

    # NOTE(kevinbenton): sorting and grouping chains is for determinism in
    # tests. iptables doesn't care about the order here
    statements = [':%s - [0:0]' % c for c in sorted(new_chains - old_chains)]
    sg_chains = []
    other_chains = []
    for chain in sorted(old_chains | new_chains):
        if '-sg-' in chain:
            sg_chains.append(chain)
        else:
            other_chains.append(chain)

    for chain in other_chains + sg_chains:
        statements += _generate_chain_diff_iptables_commands(
            chain, old_by_chain[chain], new_by_chain[chain])
    # unreferenced chains get the axe
    for chain in sorted(old_chains - new_chains):
        statements += ['-X %s' % chain]
    return statements


def _get_rules_by_chain(rules):
    by_chain = collections.defaultdict(list)
    for line in rules:
        if line.startswith(':'):
            chain = line[1:].split(' ', 1)[0]
            # even though this is a default dict, we need to manually add
            # chains to ensure that ones without rules are included because
            # they might be a jump reference
            if chain not in by_chain:
                by_chain[chain] = []
        elif line.startswith('-A'):
            chain = line[3:].split(' ', 1)[0]
            by_chain[chain].append(line)
    return by_chain


def _ensure_all_mac_addresses_are_uppercase(rules):

    def _to_upper(pat):
        return pat.group(0).upper()

    new_rules = []
    lowercase_mac_regex = re.compile(r"(?:[0-9a-f]{2}[:]){5}(?:[0-9a-f]{2})")
    for rule in rules:
        new_rules.append(re.sub(lowercase_mac_regex, _to_upper, rule))
    return new_rules


def _generate_chain_diff_iptables_commands(chain, old_chain_rules,
                                           new_chain_rules):
    # keep track of the old index because we have to insert rules
    # in the right position
    old_index = 1
    statements = []
    # NOTE(slaweq): Different operating systems may return MAC addresses in the
    # itables-save's output in lowercase or uppercase. As
    # neutron.agent.linux.iptables_firewall module always keeps rules with MAC
    # addresses with uppercase, we need to ensure here that all rules are
    # stored in the same way
    old_chain_rules = _ensure_all_mac_addresses_are_uppercase(old_chain_rules)
    new_chain_rules = _ensure_all_mac_addresses_are_uppercase(new_chain_rules)
    for line in difflib.ndiff(old_chain_rules, new_chain_rules):
        if line.startswith('?'):
            # skip ? because that's a guide string for intraline differences
            continue
        if line.startswith('-'):  # line deleted
            statements.append('-D %s %d' % (chain, old_index))
            # since we are removing a line from the old rules, we
            # backup the index by 1
            old_index -= 1
        elif line.startswith('+'):  # line added
            # strip the chain name since we have to add it before the index
            rule = line[5:].split(' ', 1)[-1]
            # IptablesRule does not add trailing spaces for rules, so we
            # have to detect that here by making sure this chain isn't
            # referencing itself
            if rule == chain:
                rule = ''
            # rule inserted at this position
            statements.append('-I %s %d %s' % (chain, old_index, rule))
        old_index += 1
    return statements
