# Copyright (c) 2015 Openstack Foundation
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

import shutil

from neutron.agent.l3 import router_info as router
from neutron.agent.linux import keepalived
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class HaRouter(router.RouterInfo):
    def __init__(self, *args, **kwargs):
        super(HaRouter, self).__init__(*args, **kwargs)

        self.ha_port = None
        self.keepalived_manager = None

    def _verify_ha(self):
        # TODO(Carl) Remove when is_ha below is removed.
        if not self.is_ha:
            raise ValueError(_('Router %s is not a HA router') %
                             self.router_id)

    @property
    def is_ha(self):
        # TODO(Carl) Remove when refactoring to use sub-classes is complete.
        return self.router is not None

    @property
    def ha_priority(self):
        self._verify_ha()
        return self.router.get('priority', keepalived.HA_DEFAULT_PRIORITY)

    @property
    def ha_vr_id(self):
        self._verify_ha()
        return self.router.get('ha_vr_id')

    @property
    def ha_state(self):
        self._verify_ha()
        ha_state_path = self.keepalived_manager._get_full_config_file_path(
            'state')
        try:
            with open(ha_state_path, 'r') as f:
                return f.read()
        except (OSError, IOError):
            LOG.debug('Error while reading HA state for %s', self.router_id)
            return None

    def spawn_keepalived(self):
        self.keepalived_manager.spawn_or_restart()

    def disable_keepalived(self):
        self.keepalived_manager.disable()
        conf_dir = self.keepalived_manager.get_conf_dir()
        shutil.rmtree(conf_dir)
