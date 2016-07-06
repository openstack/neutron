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

from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc

from neutron._i18n import _
from neutron.extensions import portbindings
from neutron.extensions import trunk
from neutron import manager
from neutron.objects import trunk as trunk_objects
from neutron.services.trunk import exceptions as trunk_exc


# This layer is introduced for keeping busines logic and
# data persistence decoupled.

class TrunkPortValidator(object):

    def __init__(self, port_id):
        self.port_id = port_id

    def validate(self, context):
        """Validate that the port can be used in a trunk."""
        # TODO(tidwellr): there is a chance of a race between the
        # time these checks are performed and the time the trunk
        # creation is executed. To be revisited, if it bites.

        # Validate that the given port_id is not used by a subport.
        subports = trunk_objects.SubPort.get_objects(
            context, port_id=self.port_id)
        if subports:
            raise trunk_exc.TrunkPortInUse(port_id=self.port_id)

        # Validate that the given port_id is not used by a trunk.
        trunks = trunk_objects.Trunk.get_objects(context, port_id=self.port_id)
        if trunks:
            raise trunk_exc.ParentPortInUse(port_id=self.port_id)

        if self.is_bound(context):
            raise trunk_exc.ParentPortInUse(port_id=self.port_id)

        return self.port_id

    def is_bound(self, context):
        """Return true if the port is bound, false otherwise."""
        # Validate that the given port_id does not have a port binding.
        core_plugin = manager.NeutronManager.get_plugin()
        port = core_plugin.get_port(context, self.port_id)
        device_owner = port.get('device_owner', '')
        return port.get(portbindings.HOST_ID) or \
            device_owner.startswith(n_const.DEVICE_OWNER_COMPUTE_PREFIX)


class SubPortsValidator(object):

    def __init__(self, segmentation_types, subports, trunk_port_id=None):
        self._segmentation_types = segmentation_types
        self.subports = subports
        self.trunk_port_id = trunk_port_id

    def validate(self, context,
                 basic_validation=False, trunk_validation=True):
        """Validate that subports can be used in a trunk."""
        # Perform basic validation on subports, in case subports
        # are not automatically screened by the API layer.
        if basic_validation:
            msg = trunk.validate_subports(self.subports)
            if msg:
                raise n_exc.InvalidInput(error_message=msg)
        if trunk_validation:
            return [self._validate(context, s) for s in self.subports]
        else:
            return self.subports

    def _validate(self, context, subport):
        # Check that the subport doesn't reference the same port_id as a
        # trunk we may be in the middle of trying to create, in other words
        # make the validation idiot proof.
        if subport['port_id'] == self.trunk_port_id:
            raise trunk_exc.ParentPortInUse(port_id=subport['port_id'])

        # If the segmentation details are missing, we will need to
        # figure out defaults when the time comes to support Ironic.
        # We can reasonably expect segmentation details to be provided
        # in all other cases for now.
        segmentation_id = subport.get("segmentation_id")
        segmentation_type = subport.get("segmentation_type")
        if not segmentation_id or not segmentation_type:
            msg = _("Invalid subport details '%s': missing segmentation "
                    "information. Must specify both segmentation_id and "
                    "segmentation_type") % subport
            raise n_exc.InvalidInput(error_message=msg)

        if segmentation_type not in self._segmentation_types:
            msg = _("Invalid segmentation_type '%s'") % segmentation_type
            raise n_exc.InvalidInput(error_message=msg)

        if not self._segmentation_types[segmentation_type](segmentation_id):
            msg = _("Invalid segmentation id '%s'") % segmentation_id
            raise n_exc.InvalidInput(error_message=msg)

        trunk_validator = TrunkPortValidator(subport['port_id'])
        trunk_validator.validate(context)
        return subport
