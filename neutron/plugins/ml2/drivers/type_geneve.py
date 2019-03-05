# Copyright (c) 2015 OpenStack Foundation
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


from neutron_lib import constants as p_const
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log

from neutron.conf.plugins.ml2.drivers import driver_type
from neutron.db.models.plugins.ml2 import geneveallocation as \
    geneve_alloc_model
from neutron.objects.plugins.ml2 import geneveallocation as geneve_obj
from neutron.plugins.ml2.drivers import type_tunnel

LOG = log.getLogger(__name__)

driver_type.register_ml2_drivers_geneve_opts()


class GeneveTypeDriver(type_tunnel.EndpointTunnelTypeDriver):

    def __init__(self):
        super(GeneveTypeDriver, self).__init__(geneve_obj.GeneveAllocation,
                                               geneve_obj.GeneveEndpoint)
        self.max_encap_size = cfg.CONF.ml2_type_geneve.max_header_size
        self.model_segmentation_id = (
            geneve_alloc_model.GeneveAllocation.geneve_vni)

    def get_type(self):
        return p_const.TYPE_GENEVE

    def initialize(self):
        try:
            self._initialize(cfg.CONF.ml2_type_geneve.vni_ranges)
        except n_exc.NetworkTunnelRangeError:
            LOG.error("Failed to parse vni_ranges. Service terminated!")
            raise SystemExit()

    def get_endpoints(self):
        """Get every geneve endpoints from database."""
        geneve_endpoints = self._get_endpoints()
        return [{'ip_address': geneve_endpoint.ip_address,
                 'host': geneve_endpoint.host}
                for geneve_endpoint in geneve_endpoints]

    def add_endpoint(self, ip, host):
        return self._add_endpoint(ip, host)

    def get_mtu(self, physical_network=None):
        mtu = super(GeneveTypeDriver, self).get_mtu()
        return mtu - self.max_encap_size if mtu else 0
