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

from oslo_config import cfg

from neutron.common import config
from neutron.common import profiler


def eventlet_api_server():
    if os.environ.get('PYTHONWARNINGS') == 'ignore:Unverified HTTPS request':
        import urllib3  # pylint: disable=import-outside-toplevel
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    profiler.setup('neutron-server', cfg.CONF.host)
    return config.load_paste_app('neutron')
