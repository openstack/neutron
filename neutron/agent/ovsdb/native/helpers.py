# Copyright (c) 2015 Red Hat, Inc.
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

import functools

from ovsdbapp.schema.open_vswitch import helpers

from neutron.agent.common import utils

enable_connection_uri = functools.partial(
    helpers.enable_connection_uri, execute=utils.execute, run_as_root=True,
    log_fail_as_error=False, check_exit_code=False)
