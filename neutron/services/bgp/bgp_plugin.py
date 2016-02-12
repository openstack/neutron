# Copyright 2016 Hewlett Packard Enterprise Development Company LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg
from oslo_utils import importutils

from neutron.db import bgp_db
from neutron.db import bgp_dragentscheduler_db
from neutron.extensions import bgp as bgp_ext
from neutron.extensions import bgp_dragentscheduler as dras_ext
from neutron.services import service_base

PLUGIN_NAME = bgp_ext.BGP_EXT_ALIAS + '_svc_plugin'


class BgpPlugin(service_base.ServicePluginBase,
                bgp_db.BgpDbMixin,
                bgp_dragentscheduler_db.BgpDrAgentSchedulerDbMixin):

    supported_extension_aliases = [bgp_ext.BGP_EXT_ALIAS,
                                   dras_ext.BGP_DRAGENT_SCHEDULER_EXT_ALIAS]

    def __init__(self):
        super(BgpPlugin, self).__init__()
        self.bgp_drscheduler = importutils.import_object(
            cfg.CONF.bgp_drscheduler_driver)

    def get_plugin_name(self):
        return PLUGIN_NAME

    def get_plugin_type(self):
        return bgp_ext.BGP_EXT_ALIAS

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("BGP dynamic routing service for announcement of next-hops "
                "for tenant networks, floating IP's, and DVR host routes.")
