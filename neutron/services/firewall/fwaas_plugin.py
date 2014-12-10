# Copyright 2014 A10 Networks, Inc
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

from neutron.i18n import _LE
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

try:
    from neutron_fwaas.services.firewall import fwaas_plugin
except Exception as e:
    LOG.error(_LE("Firewall service plugin requires neutron-fwaas module"))
    raise e


class FirewallPlugin(fwaas_plugin.FirewallPlugin):
    pass
