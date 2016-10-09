# Copyright (c) 2015 Cisco Systems.
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
import sys

from neutron_lib.utils import file as file_utils


def main():
    """Expected arguments:
    sys.argv[1] - The add/update/delete operation performed by the PD agent
    sys.argv[2] - The file where the new prefix should be written
    sys.argv[3] - The process ID of the L3 agent to be notified of this change
    """
    operation = sys.argv[1]
    prefix_fname = sys.argv[2]
    agent_pid = sys.argv[3]
    prefix = os.getenv('PREFIX1', "::")

    if operation == "add" or operation == "update":
        file_utils.replace_file(prefix_fname, "%s/64" % prefix)
    elif operation == "delete":
        file_utils.replace_file(prefix_fname, "::/64")
    os.kill(int(agent_pid), signal.SIGUSR1)
