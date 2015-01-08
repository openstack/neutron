# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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

from oslo_config import cfg

from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_db
from neutron.i18n import _LE, _LW
from neutron.openstack.common import log as logging
from neutronclient.common import exceptions
from neutronclient.v2_0 import client


LOG = logging.getLogger(__name__)


class ProxyPluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                    external_net_db.External_net_db_mixin,
                    l3_db.L3_NAT_db_mixin):
    supported_extension_aliases = ["external-net", "router"]

    def __init__(self, configfile=None):
        super(ProxyPluginV2, self).__init__()
        self.neutron = client.Client(
            username=cfg.CONF.PROXY.admin_user,
            password=cfg.CONF.PROXY.admin_password,
            tenant_name=cfg.CONF.PROXY.admin_tenant_name,
            auth_url=cfg.CONF.PROXY.auth_url,
            auth_strategy=cfg.CONF.PROXY.auth_strategy,
            region_name=cfg.CONF.PROXY.auth_region
        )

    def _get_client(self):
        return self.neutron

    def create_subnet(self, context, subnet):
        subnet_remote = self._get_client().create_subnet(subnet)
        subnet['subnet']['id'] = subnet_remote['id']
        tenant_id = self._get_tenant_id_for_create(context, subnet['subnet'])
        subnet['subnet']['tenant_id'] = tenant_id
        try:
            subnet_in_db = super(ProxyPluginV2, self).create_subnet(
                context, subnet)
        except Exception:
            self._get_client().delete_subnet(subnet_remote['id'])
        return subnet_in_db

    def update_subnet(self, context, id, subnet):
        subnet_in_db = super(ProxyPluginV2, self).update_subnet(
            context, id, subnet)
        try:
            self._get_client().update_subnet(id, subnet)
        except Exception as e:
            LOG.error(_LE("Update subnet failed: %s"), e)
        return subnet_in_db

    def delete_subnet(self, context, id):
        try:
            self._get_client().delete_subnet(id)
        except exceptions.NotFound:
            LOG.warn(_LW("Subnet in remote have already deleted"))
        return super(ProxyPluginV2, self).delete_subnet(context, id)

    def create_network(self, context, network):
        network_remote = self._get_client().create_network(network)
        network['network']['id'] = network_remote['id']
        tenant_id = self._get_tenant_id_for_create(context, network['network'])
        network['network']['tenant_id'] = tenant_id
        try:
            network_in_db = super(ProxyPluginV2, self).create_network(
                context, network)
        except Exception:
            self._get_client().delete_network(network_remote['id'])
        return network_in_db

    def update_network(self, context, id, network):
        network_in_db = super(ProxyPluginV2, self).update_network(
            context, id, network)
        try:
            self._get_client().update_network(id, network)
        except Exception as e:
            LOG.error(_LE("Update network failed: %s"), e)
        return network_in_db

    def delete_network(self, context, id):
        try:
            self._get_client().delete_network(id)
        except exceptions.NetworkNotFoundClient:
            LOG.warn(_LW("Network in remote have already deleted"))
        return super(ProxyPluginV2, self).delete_network(context, id)

    def create_port(self, context, port):
        port_remote = self._get_client().create_port(port)
        port['port']['id'] = port_remote['id']
        tenant_id = self._get_tenant_id_for_create(context, port['port'])
        port['port']['tenant_id'] = tenant_id
        try:
            port_in_db = super(ProxyPluginV2, self).create_port(
                context, port)
        except Exception:
            self._get_client().delete_port(port_remote['id'])
        return port_in_db

    def update_port(self, context, id, port):
        port_in_db = super(ProxyPluginV2, self).update_port(
            context, id, port)
        try:
            self._get_client().update_port(id, port)
        except Exception as e:
            LOG.error(_LE("Update port failed: %s"), e)
        return port_in_db

    def delete_port(self, context, id, l3_port_check=True):
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        self.disassociate_floatingips(context, id)

        try:
            self._get_client().delete_port(id)
        except exceptions.PortNotFoundClient:
            LOG.warn(_LW("Port in remote have already deleted"))
        return super(ProxyPluginV2, self).delete_port(context, id)
