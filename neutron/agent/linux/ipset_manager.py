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

import copy

import netaddr

from neutron.agent.linux import utils as linux_utils
from oslo_concurrency import lockutils

IPSET_ADD_BULK_THRESHOLD = 5
NET_PREFIX = 'N'
SWAP_SUFFIX = '-n'
IPSET_NAME_MAX_LENGTH = 31 - len(SWAP_SUFFIX)


class IpsetManager(object):
    """Smart wrapper for ipset.

       Keeps track of ip addresses per set, using bulk
       or single ip add/remove for smaller changes.
    """

    def __init__(self, execute=None, namespace=None):
        self.execute = execute or linux_utils.execute
        self.namespace = namespace
        self.ipset_sets = {}

    def _sanitize_addresses(self, addresses):
        """This method converts any address to ipset format.

        If an address has a mask of /0 we need to cover to it to a mask of
        /1 as ipset does not support /0 length addresses. Instead we use two
        /1's to represent the /0.
        """
        sanitized_addresses = []
        for ip, _mac in addresses:
            ip = netaddr.IPNetwork(ip)
            if ip.prefixlen == 0:
                if ip.version == 4:
                    sanitized_addresses.append('0.0.0.0/1')
                    sanitized_addresses.append('128.0.0.0/1')
                elif ip.version == 6:
                    sanitized_addresses.append('::/1')
                    sanitized_addresses.append('8000::/1')
            else:
                sanitized_addresses.append(str(ip))
        return sanitized_addresses

    @staticmethod
    def get_name(id, ethertype):
        """Returns the given ipset name for an id+ethertype pair.
        This reference can be used from iptables.
        """
        name = NET_PREFIX + ethertype + id
        return name[:IPSET_NAME_MAX_LENGTH]

    def set_name_exists(self, set_name):
        """Returns true if the set name is known to the manager."""
        return set_name in self.ipset_sets

    def set_members(self, id, ethertype, member_ips):
        """Create or update a specific set by name and ethertype.
        It will make sure that a set is created, updated to
        add / remove new members, or swapped atomically if
        that's faster, and return added / removed members.
        """
        member_ips = self._sanitize_addresses(member_ips)
        set_name = self.get_name(id, ethertype)
        add_ips = self._get_new_set_ips(set_name, member_ips)
        del_ips = self._get_deleted_set_ips(set_name, member_ips)
        if add_ips or del_ips or not self.set_name_exists(set_name):
            self.set_members_mutate(set_name, ethertype, member_ips)
        return add_ips, del_ips

    def set_members_mutate(self, set_name, ethertype, member_ips):
        with lockutils.lock('neutron-ipset-%s' % self.namespace,
                            external=True):
            if not self.set_name_exists(set_name):
                # The initial creation is handled with create/refresh to
                # avoid any downtime for existing sets (i.e. avoiding
                # a flush/restore), as the restore operation of ipset is
                # additive to the existing set.
                self._create_set(set_name, ethertype)
                self._refresh_set(set_name, member_ips, ethertype)
                # TODO(majopela,shihanzhang,haleyb): Optimize this by
                # gathering the system ipsets at start. So we can determine
                # if a normal restore is enough for initial creation.
                # That should speed up agent boot up time.
            else:
                add_ips = self._get_new_set_ips(set_name, member_ips)
                del_ips = self._get_deleted_set_ips(set_name, member_ips)
                if (len(add_ips) + len(del_ips) < IPSET_ADD_BULK_THRESHOLD):
                    self._add_members_to_set(set_name, add_ips)
                    self._del_members_from_set(set_name, del_ips)
                else:
                    self._refresh_set(set_name, member_ips, ethertype)

    def destroy(self, id, ethertype, forced=False):
        with lockutils.lock('neutron-ipset-%s' % self.namespace,
                            external=True):
            set_name = self.get_name(id, ethertype)
            self._destroy(set_name, forced)

    def _add_member_to_set(self, set_name, member_ip):
        cmd = ['ipset', 'add', '-exist', set_name, member_ip]
        self._apply(cmd)
        self.ipset_sets[set_name].append(member_ip)

    def _refresh_set(self, set_name, member_ips, ethertype):
        new_set_name = set_name + SWAP_SUFFIX
        set_type = self._get_ipset_set_type(ethertype)
        process_input = ["create %s hash:net family %s" % (new_set_name,
                                                           set_type)]
        for ip in member_ips:
            process_input.append("add %s %s" % (new_set_name, ip))

        self._restore_sets(process_input)
        self._swap_sets(new_set_name, set_name)
        self._destroy(new_set_name, True)
        self.ipset_sets[set_name] = copy.copy(member_ips)

    def _del_member_from_set(self, set_name, member_ip):
        cmd = ['ipset', 'del', set_name, member_ip]
        self._apply(cmd, fail_on_errors=False)
        self.ipset_sets[set_name].remove(member_ip)

    def _create_set(self, set_name, ethertype):
        cmd = ['ipset', 'create', '-exist', set_name, 'hash:net', 'family',
               self._get_ipset_set_type(ethertype)]
        self._apply(cmd)
        self.ipset_sets[set_name] = []

    def _apply(self, cmd, input=None, fail_on_errors=True):
        input = '\n'.join(input) if input else None
        cmd_ns = []
        if self.namespace:
            cmd_ns.extend(['ip', 'netns', 'exec', self.namespace])
        cmd_ns.extend(cmd)
        self.execute(cmd_ns, run_as_root=True, process_input=input,
                     check_exit_code=fail_on_errors, privsep_exec=True)

    def _get_new_set_ips(self, set_name, expected_ips):
        new_member_ips = (set(expected_ips) -
                          set(self.ipset_sets.get(set_name, [])))
        return list(new_member_ips)

    def _get_deleted_set_ips(self, set_name, expected_ips):
        deleted_member_ips = (set(self.ipset_sets.get(set_name, [])) -
                              set(expected_ips))
        return list(deleted_member_ips)

    def _add_members_to_set(self, set_name, add_ips):
        for ip in add_ips:
            if ip not in self.ipset_sets[set_name]:
                self._add_member_to_set(set_name, ip)

    def _del_members_from_set(self, set_name, del_ips):
        for ip in del_ips:
            if ip in self.ipset_sets[set_name]:
                self._del_member_from_set(set_name, ip)

    def _get_ipset_set_type(self, ethertype):
        return 'inet6' if ethertype == 'IPv6' else 'inet'

    def _restore_sets(self, process_input):
        cmd = ['ipset', 'restore', '-exist']
        self._apply(cmd, process_input)

    def _swap_sets(self, src_set, dest_set):
        cmd = ['ipset', 'swap', src_set, dest_set]
        self._apply(cmd)

    def _destroy(self, set_name, forced=False):
        if set_name in self.ipset_sets or forced:
            cmd = ['ipset', 'destroy', set_name]
            self._apply(cmd, fail_on_errors=False)
            self.ipset_sets.pop(set_name, None)
