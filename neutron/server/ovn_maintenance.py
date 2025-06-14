# Copyright 2024 Red Hat, Inc.
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

from neutron_lib.api import attributes
from oslo_log import log

from neutron._i18n import _
from neutron.api import extensions
from neutron import manager
from neutron import service

LOG = log.getLogger(__name__)


def ovn_maintenance_worker():
    LOG.info('OVN maintenance process starting...')

    try:
        manager.init()
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        ext_mgr.extend_resources('2.0', attributes.RESOURCES)
        ovn_maintenance_worker = service.start_ovn_maintenance_worker()
        if not ovn_maintenance_worker:
            raise RuntimeError(_('OVN maintenance worker not loaded, ML2/OVN '
                                 'mechanism driver must be used'))
    except NotImplementedError:
        LOG.info('OVN maintenance worker was already started in parent '
                 'process by plugin.')
    else:
        ovn_maintenance_worker.wait()
