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

from neutron.plugins.nec import ofc_driver_base


class StubOFCDriver(ofc_driver_base.OFCDriverBase):

    def __init__(self, conf):
        pass

    def create_tenant(self, description, tenant_id=None):
        return "ofc-" + tenant_id[:-4]

    def delete_tenant(self, ofc_tenant_id):
        pass

    def create_network(self, ofc_tenant_id, description, network_id=None):
        return "ofc-" + network_id[:-4]

    def update_network(self, ofc_network_id, description):
        pass

    def delete_network(self, ofc_network_id):
        pass

    def create_port(self, ofc_network_id, info, port_id=None):
        return "ofc-" + port_id[:-4]

    def delete_port(self, ofc_port_id):
        pass

    @classmethod
    def filter_supported(cls):
        return True

    def create_filter(self, ofc_network_id, filter_dict,
                      portinfo=None, filter_id=None):
        return "ofc-" + filter_id[:-4]

    def delete_filter(self, ofc_filter_id):
        pass

    def convert_ofc_tenant_id(self, context, ofc_tenant_id):
        return ofc_tenant_id

    def convert_ofc_network_id(self, context, ofc_network_id, tenant_id):
        return ofc_network_id

    def convert_ofc_port_id(self, context, ofc_port_id, tenant_id, network_id):
        return ofc_port_id

    def convert_ofc_filter_id(self, context, ofc_filter_id):
        return ofc_filter_id
