#
# Copyright (c) 2022, OVH SAS
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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from oslo_config import cfg

from neutron.api import wsgi
from neutron.common import config
from neutron.common import profiler


def api_server():
    profiler.setup('neutron-server', cfg.CONF.host)
    app = config.load_paste_app('neutron')
    registry.publish(resources.PROCESS, events.BEFORE_SPAWN,
                     wsgi.WorkerService)
    registry.publish(resources.PROCESS, events.AFTER_INIT,
                     wsgi.WorkerService)
    return app
