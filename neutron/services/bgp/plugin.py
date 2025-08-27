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

from neutron_lib.callbacks import registry
from neutron_lib.services import base as service_base
from oslo_config import cfg
from oslo_log import log

from neutron.conf.services import bgp as bgp_config
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
