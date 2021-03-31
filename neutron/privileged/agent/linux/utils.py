# Copyright 2020 Red Hat, Inc.
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
import re

from oslo_concurrency import processutils
from oslo_utils import fileutils

from neutron import privileged


NETSTAT_PIDS_REGEX = re.compile(r'.* (?P<pid>\d{2,6})/.*')


@privileged.default.entrypoint
def find_listen_pids_namespace(namespace):
    return _find_listen_pids_namespace(namespace)


def _find_listen_pids_namespace(namespace):
    """Retrieve a list of pids of listening processes within the given netns

    This method is implemented separately to allow unit testing.
    """
    pids = set()
    cmd = ['ip', 'netns', 'exec', namespace, 'netstat', '-nlp']
    output = processutils.execute(*cmd)
    for line in output[0].splitlines():
        m = NETSTAT_PIDS_REGEX.match(line)
        if m:
            pids.add(m.group('pid'))
    return list(pids)


@privileged.default.entrypoint
def delete_if_exists(path, remove=os.unlink):
    fileutils.delete_if_exists(path, remove=remove)
