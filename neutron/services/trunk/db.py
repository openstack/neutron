# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
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

from oslo_db import exception as db_exc
from oslo_utils import uuidutils

from neutron.services.trunk import exceptions
from neutron.services.trunk import models


def create_trunk(context, port_id, description=None):
    """Create a trunk (with description) given the parent port uuid."""
    try:
        with context.session.begin(subtransactions=True):
            context.session.add(
                models.Trunk(
                    id=uuidutils.generate_uuid(),
                    tenant_id=context.tenant_id,
                    port_id=port_id,
                    description=description))
    except db_exc.DBDuplicateEntry:
        raise exceptions.TrunkPortInUse(port_id=port_id)
