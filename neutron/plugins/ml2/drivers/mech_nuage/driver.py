# Copyright 2014 Alcatel-Lucent USA Inc.
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

import netaddr
from oslo_config import cfg
from oslo_log import log

from neutron.common import constants as n_consts
from neutron.extensions import portbindings
from neutron.i18n import _LE
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from nuage_neutron.plugins.nuage.common import config
from nuage_neutron.plugins.nuage.common import constants as nuage_const
from nuage_neutron.plugins.nuage import plugin

LOG = log.getLogger(__name__)


class NuageMechanismDriver(plugin.NuagePlugin,
                           api.MechanismDriver):

    def initialize(self):
        LOG.debug('Initializing driver')
        config.nuage_register_cfg_opts()
        self.nuageclient_init()
        self.vif_type = portbindings.VIF_TYPE_OVS
        self.vif_details = {portbindings.CAP_PORT_FILTER: False}
        self.default_np_id = self.nuageclient.get_net_partition_id_by_name(
            cfg.CONF.RESTPROXY.default_net_partition_name)
        LOG.debug('Initializing complete')

    def create_subnet_postcommit(self, context):
        subnet = context.current
        net = netaddr.IPNetwork(subnet['cidr'])
        params = {
            'netpart_id': self.default_np_id,
            'tenant_id': subnet['tenant_id'],
            'net': net
        }
        self.nuageclient.create_subnet(subnet, params)

    def delete_subnet_postcommit(self, context):
        subnet = context.current
        self.nuageclient.delete_subnet(subnet['id'])

    def update_port_postcommit(self, context):
        port = context.current
        port_prefix = nuage_const.NOVA_PORT_OWNER_PREF
        # Check two things prior to proceeding with
        # talking to backend.
        # 1) binding has happened successfully.
        # 2) Its a VM port.
        if ((not context.original_top_bound_segment and
             context.top_bound_segment) and
            port['device_owner'].startswith(port_prefix)):
                np_name = cfg.CONF.RESTPROXY.default_net_partition_name
                self._create_update_port(context._plugin_context,
                                         port, np_name)

    def delete_port_postcommit(self, context):
        port = context.current
        np_name = cfg.CONF.RESTPROXY.default_net_partition_name
        self._delete_nuage_vport(context._plugin_context,
                                 port, np_name)

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        for segment in context.segments_to_bind:
            if self._check_segment(segment):
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details,
                                    status=n_consts.PORT_STATUS_ACTIVE)
                LOG.debug("Bound using segment: %s", segment)
                return
            else:
                LOG.error(_LE("Refusing to bind port for segment ID %(id)s, "
                              "segment %(seg)s, phys net %(physnet)s, and "
                              "network type %(nettype)s"),
                          {'id': segment[api.ID],
                           'seg': segment[api.SEGMENTATION_ID],
                           'physnet': segment[api.PHYSICAL_NETWORK],
                           'nettype': segment[api.NETWORK_TYPE]})

    def _check_segment(self, segment):
        """Verify a segment is valid for the Nuage MechanismDriver."""
        network_type = segment[api.NETWORK_TYPE]
        return network_type in [constants.TYPE_LOCAL, constants.TYPE_GRE,
                                constants.TYPE_VXLAN, constants.TYPE_VLAN]
