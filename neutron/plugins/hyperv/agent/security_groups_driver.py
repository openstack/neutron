#Copyright 2014 Cloudbase Solutions SRL
#All Rights Reserved.
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

from debtcollector import moves
from hyperv.neutron import security_groups_driver as sg_driver
from oslo_log import log as logging

from neutron._i18n import _LW

LOG = logging.getLogger(__name__)

# TODO(claudiub): Remove this module at the beginning of the O cycle.

new_driver = 'hyperv.neutron.security_groups_driver.HyperVSecurityGroupsDriver'
LOG.warn(_LW("You are using the deprecated firewall driver: %(deprecated)s. "
             "Use the recommended driver %(new)s instead."),
         {'deprecated': '%s.HyperVSecurityGroupsDriver' % __name__,
          'new': new_driver})

HyperVSecurityGroupsDriver = moves.moved_class(
    sg_driver.HyperVSecurityGroupsDriver,
    'HyperVSecurityGroupsDriver', __name__)
