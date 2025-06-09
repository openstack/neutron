# Copyright (c) 2024 Red Hat, Inc.
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

from neutron.api import extensions
from neutron import manager
from neutron import service

LOG = log.getLogger(__name__)


def periodic_workers():
    LOG.info('Periodic workers process starting...')

    try:
        manager.init()
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        ext_mgr.extend_resources('2.0', attributes.RESOURCES)
        periodic_workers_launcher = service.start_periodic_workers()
    except NotImplementedError:
        LOG.info('Periodic workers process was already started in '
                 'parent process by plugin.')
    else:
        periodic_workers_launcher.wait()
