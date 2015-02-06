# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import mock
from novaclient import exceptions as nova_exc
from oslo_config import cfg
from oslo_utils import excutils

from neutron import context as n_context
from neutron.i18n import _LE
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants

LOG = logging.getLogger(__name__)


_uuid = uuidutils.generate_uuid


class DeviceHandlingTestSupportMixin(object):

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _mock_l3_admin_tenant(self):
        # Mock l3 admin tenant
        self.tenant_id_fcn_p = mock.patch(
            'neutron.plugins.cisco.db.l3.device_handling_db.'
            'DeviceHandlingMixin.l3_tenant_id')
        self.tenant_id_fcn = self.tenant_id_fcn_p.start()
        self.tenant_id_fcn.return_value = "L3AdminTenantId"

    def _create_mgmt_nw_for_tests(self, fmt):
        self._mgmt_nw = self._make_network(fmt,
                                           cfg.CONF.general.management_network,
                                           True, tenant_id="L3AdminTenantId",
                                           shared=False)
        self._mgmt_subnet = self._make_subnet(fmt, self._mgmt_nw,
                                              "10.0.100.1", "10.0.100.0/24",
                                              ip_version=4)

    def _remove_mgmt_nw_for_tests(self):
        q_p = "network_id=%s" % self._mgmt_nw['network']['id']
        subnets = self._list('subnets', query_params=q_p)
        if subnets:
            for p in self._list('ports', query_params=q_p).get('ports'):
                self._delete('ports', p['id'])
            self._delete('subnets', self._mgmt_subnet['subnet']['id'])
            self._delete('networks', self._mgmt_nw['network']['id'])

    # Function used to mock novaclient services list
    def _novaclient_services_list(self, all=True):
        services = set(['nova-conductor', 'nova-cert', 'nova-scheduler',
                        'nova-compute', 'nova-consoleauth'])
        full_list = [FakeResource(binary=res) for res in services]
        _all = all

        def response():
            if _all:
                return full_list
            else:
                return full_list[2:]
        return response

    # Function used to mock novaclient servers create
    def _novaclient_servers_create(self, instance_name, image_id, flavor_id,
                                   nics, files, config_drive):
        fake_vm = FakeResource()
        for nic in nics:
            p_dict = {'port': {'device_id': fake_vm.id,
                               'device_owner': 'nova'}}
            self._core_plugin.update_port(n_context.get_admin_context(),
                                          nic['port-id'], p_dict)
        return fake_vm

    # Function used to mock novaclient servers delete
    def _novaclient_servers_delete(self, vm_id):
        q_p = "device_id=%s" % vm_id
        ports = self._list('ports', query_params=q_p)
        for port in ports.get('ports', []):
            try:
                self._delete('ports', port['id'])
            except Exception as e:
                with excutils.save_and_reraise_exception(reraise=False):
                    LOG.error(_LE('Failed to delete port %(p_id)s for vm '
                                  'instance %(v_id)s due to %(err)s'),
                              {'p_id': port['id'], 'v_id': vm_id, 'err': e})
                    raise nova_exc.InternalServerError()

    def _mock_svc_vm_create_delete(self, plugin):
        # Mock novaclient methods for creation/deletion of service VMs
        mock.patch(
            'neutron.plugins.cisco.l3.service_vm_lib.n_utils.find_resource',
            lambda *args, **kw: FakeResource()).start()
        self._nclient_services_mock = mock.MagicMock()
        self._nclient_services_mock.list = self._novaclient_services_list()
        mock.patch.object(plugin._svc_vm_mgr._nclient, 'services',
                          self._nclient_services_mock).start()
        nclient_servers_mock = mock.MagicMock()
        nclient_servers_mock.create = self._novaclient_servers_create
        nclient_servers_mock.delete = self._novaclient_servers_delete
        mock.patch.object(plugin._svc_vm_mgr._nclient, 'servers',
                          nclient_servers_mock).start()

    def _mock_io_file_ops(self):
        # Mock library functions for config drive file operations
        cfg_template = '\n'.join(['interface GigabitEthernet1',
                                  'ip address <ip> <mask>',
                                  'no shutdown'])
        m = mock.mock_open(read_data=cfg_template)
        m.return_value.__iter__.return_value = cfg_template.splitlines()
        mock.patch('neutron.plugins.cisco.l3.hosting_device_drivers.'
                   'csr1kv_hd_driver.open', m, create=True).start()

    def _test_remove_all_hosting_devices(self):
        """Removes all hosting devices created during a test."""
        plugin = manager.NeutronManager.get_service_plugins()[
            constants.L3_ROUTER_NAT]
        context = n_context.get_admin_context()
        plugin.delete_all_hosting_devices(context, True)

    def _get_fake_resource(self, tenant_id=None, id=None):
        return {'id': id or _uuid(),
                'tenant_id': tenant_id or _uuid()}

    def _get_test_context(self, user_id=None, tenant_id=None, is_admin=False):
        return n_context.Context(user_id, tenant_id, is_admin,
                                 load_admin_roles=True)


# Used to fake Glance images, Nova VMs and Nova services
class FakeResource(object):
    def __init__(self, id=None, enabled='enabled', state='up', binary=None):
        self.id = id or _uuid()
        self.status = enabled
        self.state = state
        self.binary = binary
