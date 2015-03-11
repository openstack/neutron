# Copyright 2015 IBM Corp.
#
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

from networking_ibm.sdnve.ml2 import sdnve_driver
from oslo_log import log as logging

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api

LOG = logging.getLogger(__name__)


class SdnveMechanismDriver(api.MechanismDriver):
    """Ml2 Mechanism driver for IBM SDNVE Controller"""
    def initialize(self):
        self.vif_type = portbindings.VIF_TYPE_BRIDGE
        self.vif_details = {portbindings.CAP_PORT_FILTER: False}
        self.restrict_update_subnet = ['enable_dhcp',
                                       'gateway_ip',
                                       'allocation-pool']
        self.restrict_update_network = ['router:external']
        self.sdnve_drv = sdnve_driver.SdnveDriver()

    # NETWORK
    def create_network_precommit(self, context):
        self.sdnve_drv._pre_create_network(context)

    def create_network_postcommit(self, context):
        self.sdnve_drv._create_network(context)

    def update_network_precommit(self, context):
        self.sdnve_drv._pre_update_network(context)

    def update_network_postcommit(self, context):
        self.sdnve_drv._update_network(context)

    def delete_network_postcommit(self, context):
        self.sdnve_drv._delete_network(context)

    # SUBNET
    def create_subnet_precommit(self, context):
        self.sdnve_drv._pre_create_subnet(context)

    def create_subnet_postcommit(self, context):
        self.sdnve_drv._create_subnet(context)

    def update_subnet_postcommit(self, context):
        self.sdnve_drv._update_subnet(context)

    def update_subnet_precommit(self, context):
        self.sdnve_drv._pre_update_subnet(context)

    def delete_subnet_postcommit(self, context):
        self.sdnve_drv._delete_subnet(context)

    # PORT
    def create_port_postcommit(self, context):
        self.sdnve_drv._create_port(context)

    def create_port_precommit(self, context):
        self.sdnve_drv._pre_create_port(context)

    def delete_port_precommit(self, context):
        self.sdnve_drv._pre_delete_port(context)

    def update_port_postcommit(self, context):
        self.sdnve_drv._update_port(context)

    def delete_port_postcommit(self, context):
        self.sdnve_drv._delete_port(context)

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        for segment in context.network.network_segments:
            if self.sdnve_drv._check_segment(segment):
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details,
                                    status=n_const.PORT_STATUS_ACTIVE)
                LOG.debug("Bound using segment: %s", segment)
                return
            else:
                LOG.debug("Refusing to bind port for segment ID %(id)s, "
                          "segment %(seg)s, phys net %(physnet)s, and "
                          "network type %(nettype)s",
                          {'id': segment[api.ID],
                           'seg': segment[api.SEGMENTATION_ID],
                           'physnet': segment[api.PHYSICAL_NETWORK],
                           'nettype': segment[api.NETWORK_TYPE]})
