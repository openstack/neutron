# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
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

# @author Mark McClain (DreamHost)

import sys
import warnings

from neutron import api
from neutron.api import extensions
from neutron.api import v2


warnings.warn(
    _('You are using old configuration values for the api-paste config. '
      'Please update for Neutron.')
)
sys.modules['quantum.api.extensions'] = extensions
sys.modules['quantum.api.v2'] = v2
# The following assigment must be performed at the end of the module.
# Otherwise local variables will be overwritten.
sys.modules['quantum.api'] = api
