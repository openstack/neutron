# Copyright (c) 2015 Cloudbase Solutions.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# NOTE(ralonsoh): remove once the default backend is ``BackendType.THREADING``
import os

from oslo_service import backend as oslo_service_backend
oslo_service_backend.init_backend(oslo_service_backend.BackendType.THREADING)

# NOTE: the environment variable "OSKEN_HUB_TYPE" defines the ``os-ken``
# hub type to be used. The default value is now "eventlet". Once the
# default value is set to "native", we will remove the following line.
os.environ['OSKEN_HUB_TYPE'] = 'native'


# pylint: disable=wrong-import-position, line-too-long
import setproctitle  # noqa: E402

import neutron.plugins.ml2.drivers.openvswitch.agent.main as agent_main  # noqa: E402,E501
from neutron_lib import constants  # noqa: E402


def main():
    proctitle = "{} ({})".format(
        constants.AGENT_PROCESS_OVS, setproctitle.getproctitle())
    setproctitle.setproctitle(proctitle)

    agent_main.main()
