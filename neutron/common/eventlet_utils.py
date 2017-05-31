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

import os

import eventlet
from oslo_utils import importutils


def monkey_patch():
    eventlet.monkey_patch()
    if os.name != 'nt':
        p_c_e = importutils.import_module('pyroute2.config.asyncio')
        p_c_e.asyncio_config()
