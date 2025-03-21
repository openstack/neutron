# Copyright (c) 2013 OpenStack Foundation
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
from neutron.db.models.plugins.ml2 import gre_allocation_endpoints as \
    gre_alloc_model
from neutron.objects.plugins.ml2 import greallocation as gre_obj
from neutron.plugins.ml2.drivers import type_tunnel

LOG = log.getLogger(__name__)

driver_type.register_ml2_drivers_gre_opts()


class GreTypeDriver(type_tunnel.EndpointTunnelTypeDriver):

    def __init__(self):
        super().__init__(
            gre_obj.GreAllocation, gre_obj.GreEndpoint)
        self.model_segmentation_id = gre_alloc_model.GreAllocation.gre_id

    def get_type(self):
        return p_const.TYPE_GRE

    def initialize(self):
        try:
            self._initialize(cfg.CONF.ml2_type_gre.tunnel_id_ranges)
        except n_exc.NetworkTunnelRangeError:
            LOG.exception("Failed to parse tunnel_id_ranges. "
                          "Service terminated!")
            raise SystemExit()

    def get_endpoints(self):
        """Get every gre endpoints from database."""
        gre_endpoints = self._get_endpoints()
        return [{'ip_address': gre_endpoint.ip_address,
                 'host': gre_endpoint.host}
                for gre_endpoint in gre_endpoints]

    def add_endpoint(self, ip, host):
        return self._add_endpoint(ip, host)

    def get_mtu(self, physical_network=None):
        mtu = super().get_mtu(physical_network)
        return mtu - p_const.GRE_ENCAP_OVERHEAD if mtu else 0
