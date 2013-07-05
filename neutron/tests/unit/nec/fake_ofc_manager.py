# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock


OFC_MANAGER = 'neutron.plugins.nec.nec_plugin.ofc_manager.OFCManager'


def patch_ofc_manager():
    m = mock.patch(OFC_MANAGER).start()
    f = FakeOFCManager()

    m.create_ofc_tenant.side_effect = f.create_ofc_tenant
    m.delete_ofc_tenant.side_effect = f.delete_ofc_tenant
    m.exists_ofc_tenant.side_effect = f.exists_ofc_tenant
    m.create_ofc_network.side_effect = f.create_ofc_net
    m.delete_ofc_network.side_effect = f.delete_ofc_net
    m.exists_ofc_network.side_effect = f.exists_ofc_net
    m.create_ofc_port.side_effect = f.create_ofc_port
    m.delete_ofc_port.side_effect = f.delete_ofc_port
    m.exists_ofc_port.side_effect = f.exists_ofc_port
    m.create_ofc_packet_filter.side_effect = f.create_ofc_pf
    m.delete_ofc_packet_filter.side_effect = f.delete_ofc_pf
    m.exists_ofc_packet_filter.side_effect = f.exists_ofc_pf
    m.set_raise_exc = f.set_raise_exc

    return m


class FakeOFCManager(object):

    def __init__(self):
        self.ofc_tenants = {}
        self.ofc_nets = {}
        self.ofc_ports = {}
        self.ofc_pfs = {}
        self.raise_exc_map = {}

    def set_raise_exc(self, func, raise_exc):
        self.raise_exc_map.update({func: raise_exc})

    def _raise_exc(self, func):
        exc = self.raise_exc_map.get(func)
        if exc:
            raise exc

    def create_ofc_tenant(self, context, tenant_id):
        self._raise_exc('create_ofc_tenant')
        self.ofc_tenants.update({tenant_id: True})

    def exists_ofc_tenant(self, context, tenant_id):
        self._raise_exc('exists_ofc_tenant')
        return self.ofc_tenants.get(tenant_id, False)

    def delete_ofc_tenant(self, context, tenant_id):
        self._raise_exc('delete_ofc_tenant')
        del self.ofc_tenants[tenant_id]

    def create_ofc_net(self, context, tenant_id, net_id, net_name=None):
        self._raise_exc('create_ofc_network')
        self.ofc_nets.update({net_id: True})

    def exists_ofc_net(self, context, net_id):
        self._raise_exc('exists_ofc_network')
        return self.ofc_nets.get(net_id, False)

    def delete_ofc_net(self, context, net_id, net):
        self._raise_exc('delete_ofc_network')
        del self.ofc_nets[net_id]

    def create_ofc_port(self, context, port_id, port):
        self._raise_exc('create_ofc_port')
        self.ofc_ports.update({port_id: True})

    def exists_ofc_port(self, context, port_id):
        self._raise_exc('exists_ofc_port')
        return self.ofc_ports.get(port_id, False)

    def delete_ofc_port(self, context, port_id, port):
        self._raise_exc('delete_ofc_port')
        del self.ofc_ports[port_id]

    def create_ofc_pf(self, context, pf_id, pf_dict):
        self._raise_exc('create_ofc_packet_filter')
        self.ofc_pfs.update({pf_id: True})

    def exists_ofc_pf(self, context, pf_id):
        self._raise_exc('exists_ofc_packet_filter')
        return self.ofc_pfs.get(pf_id, False)

    def delete_ofc_pf(self, context, pf_id):
        self._raise_exc('delete_ofc_packet_filter')
        del self.ofc_pfs[pf_id]
