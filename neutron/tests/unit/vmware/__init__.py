# Copyright 2013 OpenStack Foundation.
#
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

from neutron.plugins.vmware.api_client import client as nsx_client
from neutron.plugins.vmware.api_client import eventlet_client
from neutron.plugins.vmware import extensions
import neutron.plugins.vmware.plugin as neutron_plugin
from neutron.plugins.vmware.vshield import vcns


plugin = neutron_plugin.NsxPlugin
api_client = nsx_client.NsxApiClient
evt_client = eventlet_client.EventletApiClient
vcns_class = vcns.Vcns

STUBS_PATH = os.path.join(os.path.dirname(__file__), 'etc')
NSXEXT_PATH = os.path.dirname(extensions.__file__)
NSXAPI_NAME = '%s.%s' % (api_client.__module__, api_client.__name__)
PLUGIN_NAME = '%s.%s' % (plugin.__module__, plugin.__name__)
CLIENT_NAME = '%s.%s' % (evt_client.__module__, evt_client.__name__)
VCNS_NAME = '%s.%s' % (vcns_class.__module__, vcns_class.__name__)


def get_fake_conf(filename):
    return os.path.join(STUBS_PATH, filename)


def nsx_method(method_name, module_name='nsxlib'):
    return '%s.%s.%s' % ('neutron.plugins.vmware', module_name, method_name)
