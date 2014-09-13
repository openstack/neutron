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

from neutron.agent.linux import utils as linux_utils
from neutron.common import utils


class IpsetManager(object):
    """Wrapper for ipset."""

    def __init__(self, execute=None, root_helper=None, namespace=None):
        self.execute = execute or linux_utils.execute
        self.root_helper = root_helper
        self.namespace = namespace

    @utils.synchronized('ipset', external=True)
    def create_ipset_chain(self, chain_name, ethertype):
        cmd = ['ipset', 'create', '-exist', chain_name, 'hash:ip', 'family',
               self._get_ipset_chain_type(ethertype)]
        self._apply(cmd)

    @utils.synchronized('ipset', external=True)
    def add_member_to_ipset_chain(self, chain_name, member_ip):
        cmd = ['ipset', 'add', '-exist', chain_name, member_ip]
        self._apply(cmd)

    @utils.synchronized('ipset', external=True)
    def refresh_ipset_chain_by_name(self, chain_name, member_ips, ethertype):
        new_chain_name = chain_name + '-new'
        chain_type = self._get_ipset_chain_type(ethertype)
        process_input = ["create %s hash:ip family %s" % (new_chain_name,
                                                          chain_type)]
        for ip in member_ips:
            process_input.append("add %s %s" % (new_chain_name, ip))

        self._restore_ipset_chains(process_input)
        self._swap_ipset_chains(new_chain_name, chain_name)
        self._destroy_ipset_chain(new_chain_name)

    @utils.synchronized('ipset', external=True)
    def del_ipset_chain_member(self, chain_name, member_ip):
        cmd = ['ipset', 'del', chain_name, member_ip]
        self._apply(cmd)

    @utils.synchronized('ipset', external=True)
    def destroy_ipset_chain_by_name(self, chain_name):
        self._destroy_ipset_chain(chain_name)

    def _apply(self, cmd, input=None):
        input = '\n'.join(input) if input else None
        cmd_ns = []
        if self.namespace:
            cmd_ns.extend(['ip', 'netns', 'exec', self.namespace])
        cmd_ns.extend(cmd)
        self.execute(cmd_ns,
                     root_helper=self.root_helper,
                     process_input=input)

    def _get_ipset_chain_type(self, ethertype):
        return 'inet6' if ethertype == 'IPv6' else 'inet'

    def _restore_ipset_chains(self, process_input):
        cmd = ['ipset', 'restore', '-exist']
        self._apply(cmd, process_input)

    def _swap_ipset_chains(self, src_chain, dest_chain):
        cmd = ['ipset', 'swap', src_chain, dest_chain]
        self._apply(cmd)

    def _destroy_ipset_chain(self, chain_name):
        cmd = ['ipset', 'destroy', chain_name]
        self._apply(cmd)
