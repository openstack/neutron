# Copyright 2025 Red Hat, Inc.
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

from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from neutron_lib.services import base as service_base
from oslo_config import cfg
from oslo_log import log

from neutron.conf.services import bgp as bgp_config
from neutron.objects import network as network_objects
from neutron.services.bgp import worker

LOG = log.getLogger(__name__)


@registry.has_registry_receivers
class BGPServicePlugin(service_base.ServicePluginBase):

    supported_extension_aliases = []

    def __init__(self):
        LOG.info("Starting BGP Service Plugin")
        super().__init__()
        bgp_config.register_opts(cfg.CONF)

    def get_workers(self):
        return [worker.BGPWorker()]

    def get_plugin_description(self):
        return "BGP service plugin for OVN"

    @classmethod
    def get_plugin_type(cls):
        return "bgp-service"

    @registry.receives(resources.NETWORK, [events.PRECOMMIT_CREATE])
    def _validate_provider_network(self, resource, event, trigger, payload):
        network = payload.latest_state
        network_type = network.get(pnet.NETWORK_TYPE)
        if network_type == n_const.TYPE_VLAN:
            raise n_exc.BadRequest(
                resource='network',
                msg='VLAN provider networks are not supported when the '
                    'BGP service plugin is enabled. '
                    'Only flat provider networks are supported.')
        if network_type == n_const.TYPE_FLAT:
            existing = network_objects.NetworkSegment.get_objects(
                payload.context, network_type=n_const.TYPE_FLAT)
            other_flat = [s for s in existing
                          if s.network_id != payload.resource_id]
            if other_flat:
                raise n_exc.BadRequest(
                    resource='network',
                    msg='Only a single flat provider network is supported '
                        'when the BGP service plugin is enabled.')
