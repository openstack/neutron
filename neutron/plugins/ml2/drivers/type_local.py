# Copyright (c) 2013 OpenStack Foundation
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

from oslo_log import log

from neutron.common import exceptions as exc
from neutron.i18n import _LI
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)


class LocalTypeDriver(api.TypeDriver):
    """Manage state for local networks with ML2.

    The LocalTypeDriver implements the 'local' network_type. Local
    network segments provide connectivity between VMs and other
    devices running on the same node, provided that a common local
    network bridging technology is available to those devices. Local
    network segments do not provide any connectivity between nodes.
    """

    def __init__(self):
        LOG.info(_LI("ML2 LocalTypeDriver initialization complete"))

    def get_type(self):
        return p_const.TYPE_LOCAL

    def initialize(self):
        pass

    def is_partial_segment(self, segment):
        return False

    def validate_provider_segment(self, segment):
        for key, value in segment.iteritems():
            if value and key != api.NETWORK_TYPE:
                msg = _("%s prohibited for local provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        # No resources to reserve
        return segment

    def allocate_tenant_segment(self, session):
        # No resources to allocate
        return {api.NETWORK_TYPE: p_const.TYPE_LOCAL}

    def release_segment(self, session, segment):
        # No resources to release
        pass

    def get_mtu(self, physical_network=None):
        pass
