# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

import re
import uuid

from quantum.plugins.nec.common import ofc_client
from quantum.plugins.nec import ofc_driver_base


TENANTS_PATH = "/tenants"
TENANT_PATH = "/tenants/%s"
NETWORKS_PATH = "/tenants/%s/networks"
NETWORK_PATH = "/tenants/%s/networks/%s"
PORTS_PATH = "/tenants/%s/networks/%s/ports"
PORT_PATH = "/tenants/%s/networks/%s/ports/%s"


class PFCDriver(ofc_driver_base.OFCDriverBase):

    def __init__(self, conf_ofc):
        self.client = ofc_client.OFCClient(host=conf_ofc.host,
                                           port=conf_ofc.port,
                                           use_ssl=conf_ofc.use_ssl,
                                           key_file=conf_ofc.key_file,
                                           cert_file=conf_ofc.cert_file)

    @classmethod
    def filter_supported(cls):
        return False

    def create_tenant(self, description, tenant_id):
        ofc_tenant_id = self._generate_pfc_id(tenant_id)
        body = {'id': ofc_tenant_id}
        res = self.client.post(TENANTS_PATH, body=body)
        return ofc_tenant_id

    def delete_tenant(self, ofc_tenant_id):
        path = TENANT_PATH % ofc_tenant_id
        return self.client.delete(path)

    def create_network(self, ofc_tenant_id, description, network_id):
        path = NETWORKS_PATH % ofc_tenant_id
        ofc_network_id = self._generate_pfc_id(network_id)
        body = {'description': self._generate_pfc_description(description),
                'id': ofc_network_id}
        res = self.client.post(path, body=body)
        return ofc_network_id

    def update_network(self, ofc_tenant_id, ofc_network_id, description):
        path = NETWORK_PATH % (ofc_tenant_id, ofc_network_id)
        body = {'description': self._generate_pfc_description(description)}
        return self.client.put(path, body=body)

    def delete_network(self, ofc_tenant_id, ofc_network_id):
        path = NETWORK_PATH % (ofc_tenant_id, ofc_network_id)
        return self.client.delete(path)

    def create_port(self, ofc_tenant_id, ofc_network_id, portinfo, port_id):
        path = PORTS_PATH % (ofc_tenant_id, ofc_network_id)
        ofc_port_id = self._generate_pfc_id(port_id)
        body = {'datapath_id': portinfo.datapath_id,
                'port': str(portinfo.port_no),
                'vid': str(portinfo.vlan_id),
                'id': ofc_port_id}
        res = self.client.post(path, body=body)
        return ofc_port_id

    def update_port(self, ofc_tenant_id, ofc_network_id, portinfo, port_id):
        path = PORT_PATH % (ofc_tenant_id, ofc_network_id, ofc_port_id)
        body = {'datapath_id': portinfo.datapath_id,
                'port': str(portinfo.port_no),
                'vid': str(portinfo.vlan_id)}
        res = self.client.put(path, body=body)
        ofc_port_id = res['id']
        return ofc_port_id

    def delete_port(self, ofc_tenant_id, ofc_network_id, ofc_port_id):
        path = PORT_PATH % (ofc_tenant_id, ofc_network_id, ofc_port_id)
        return self.client.delete(path)

    def _generate_pfc_str(self, raw_str):
        """Generate PFC acceptable String"""
        return re.sub(r'[^0-9a-zA-Z]', '_', raw_str)

    def _generate_pfc_id(self, id_str):
        """Generate ID on PFC

        Currently, PFC ID must be less than 32.
        Shorten UUID string length from 36 to 31 by follows:
          * delete UUID Version and hyphen (see RFC4122)
          * ensure str length
        """
        try:
            # Need to use uuid.UUID to accept Keystone tenant_id as UUID
            uuid_str = str(uuid.UUID(id_str)).replace('-', '')
            # Drop version field in UUID version 4
            uuid_no_version = uuid_str[:12] + uuid_str[13:]
            return uuid_no_version[:31]
        except:
            return self._generate_pfc_str(id_str)[:31]

    def _generate_pfc_description(self, desc):
        """Generate Description on PFC

        Currently, PFC Description must be less than 128.
        """
        return self._generate_pfc_str(desc)[:127]
