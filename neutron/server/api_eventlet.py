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
import os
import signal

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from oslo_config import cfg
from oslo_reports import guru_meditation_report as gmr

from neutron.common import config
from neutron.common import profiler
from neutron import version
from neutron import wsgi


def eventlet_api_server():
    if os.environ.get('PYTHONWARNINGS') == 'ignore:Unverified HTTPS request':
        import urllib3  # pylint: disable=import-outside-toplevel
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    _version_string = version.version_info.release_string()
    gmr.TextGuruMeditation.setup_autorun(version=_version_string,
                                         signum=signal.SIGWINCH)

    profiler.setup('neutron-server', cfg.CONF.host)
    app = config.load_paste_app('neutron')
    registry.publish(resources.PROCESS, events.BEFORE_SPAWN,
                     wsgi.WorkerService)
    registry.publish(resources.PROCESS, events.AFTER_INIT,
                     wsgi.WorkerService)
    return app
