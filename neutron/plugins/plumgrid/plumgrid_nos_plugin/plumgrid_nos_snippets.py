# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 PLUMgrid, Inc. All Rights Reserved.
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
# @author: Edgar Magana, emagana@plumgrid.com, PLUMgrid, Inc.
# @author: Brenden Blanco, bblanco@plumgrid.com, PLUMgrid, Inc.

"""
Snippets needed by the PLUMgrid Plugin
"""

from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class DataNOSPLUMgrid():

    BASE_NOS_URL = '/0/connectivity/domain/'

    def __init__(self):
        LOG.info(_('NeutronPluginPLUMgrid Status: NOS Body Data Creation'))

    def create_domain_body_data(self, tenant_id):
        body_data = {"container_group": tenant_id}
        return body_data

    def create_network_body_data(self, tenant_id, topology_name):
        body_data = {"config_template": "single_bridge",
                     "container_group": tenant_id,
                     "topology_name": topology_name}
        return body_data
