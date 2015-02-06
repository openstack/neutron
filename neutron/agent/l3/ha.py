# Copyright (c) 2014 OpenStack Foundation.
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

import os

from oslo_config import cfg

from neutron.common import constants as l3_constants
from neutron.i18n import _LE
from neutron.openstack.common import log as logging
from neutron.openstack.common import periodic_task

LOG = logging.getLogger(__name__)

HA_DEV_PREFIX = 'ha-'

OPTS = [
    cfg.StrOpt('ha_confs_path',
               default='$state_path/ha_confs',
               help=_('Location to store keepalived/conntrackd '
                      'config files')),
    cfg.StrOpt('ha_vrrp_auth_type',
               default='PASS',
               help=_('VRRP authentication type AH/PASS')),
    cfg.StrOpt('ha_vrrp_auth_password',
               help=_('VRRP authentication password'),
               secret=True),
    cfg.IntOpt('ha_vrrp_advert_int',
               default=2,
               help=_('The advertisement interval in seconds')),
]


class AgentMixin(object):
    def __init__(self, host):
        self._init_ha_conf_path()
        super(AgentMixin, self).__init__(host)

    def _init_ha_conf_path(self):
        ha_full_path = os.path.dirname("/%s/" % self.conf.ha_confs_path)
        if not os.path.isdir(ha_full_path):
            os.makedirs(ha_full_path, 0o755)

    def process_ha_router_added(self, ri):
        ha_port = ri.router.get(l3_constants.HA_INTERFACE_KEY)
        if not ha_port:
            LOG.error(_LE('Unable to process HA router %s without ha port'),
                      ri.router_id)
            return

        self._set_subnet_info(ha_port)
        ri.ha_network_added(ha_port['network_id'],
                            ha_port['id'],
                            ha_port['ip_cidr'],
                            ha_port['mac_address'])
        ri.ha_port = ha_port

        ri._init_keepalived_manager()
        ri._add_keepalived_notifiers()

    def process_ha_router_removed(self, ri):
        ri.ha_network_removed()

    def get_ha_routers(self):
        return (router for router in self.router_info.values() if router.is_ha)

    @periodic_task.periodic_task
    def _ensure_keepalived_alive(self, context):
        # TODO(amuller): Use external_process.ProcessMonitor
        for router in self.get_ha_routers():
            router.keepalived_manager.revive()
