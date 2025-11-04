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
from oslo_service import backend as oslo_service_backend
oslo_service_backend.init_backend(oslo_service_backend.BackendType.THREADING)

# pylint: disable=wrong-import-position
import setproctitle  # noqa: E402

from neutron.plugins.ml2.drivers.macvtap.agent import (  # noqa: E402
    macvtap_neutron_agent as agent_main)
from neutron_lib import constants  # noqa: E402


def main():
    proctitle = "{} ({})".format(
        constants.AGENT_PROCESS_MACVTAP, setproctitle.getproctitle())
    setproctitle.setproctitle(proctitle)

    agent_main.main()
