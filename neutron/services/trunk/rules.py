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

from neutron_lib.api import converters
from neutron_lib.api import validators
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from neutron._i18n import _
from neutron.common import utils as n_utils
from neutron.extensions import portbindings
from neutron.objects import trunk as trunk_objects
from neutron.plugins.ml2 import driver_api as api
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import utils


# This layer is introduced for keeping business logic and
# data persistence decoupled.


def trunk_can_be_managed(context, trunk):
    """Validate that the trunk can be managed."""
    if not trunk.admin_state_up:
        raise trunk_exc.TrunkDisabled(trunk_id=trunk.id)


def enforce_port_deletion_rules(resource, event, trigger, **kwargs):
    """Prohibit the deletion of a port that's used in a trunk."""
    # NOTE: the ML2 plugin properly catches these exceptions when raised, but
    # non-ML2 plugins might not. To address this we should move the callback
    # registry notification emitted in the ML2 plugin's delete_port() higher
    # up in the plugin hierarchy.
    context = kwargs['context']
    port_id = kwargs['port_id']
    subport_obj = trunk_objects.SubPort.get_object(context, port_id=port_id)
    if subport_obj:
        raise trunk_exc.PortInUseAsSubPort(port_id=port_id,
                                           trunk_id=subport_obj.trunk_id)
    trunk_obj = trunk_objects.Trunk.get_object(context, port_id=port_id)
    if trunk_obj:
        raise trunk_exc.PortInUseAsTrunkParent(port_id=port_id,
                                               trunk_id=trunk_obj.id)


class TrunkPortValidator(object):

    def __init__(self, port_id):
        self.port_id = port_id
        self._port = None

    def validate(self, context, parent_port=True):
        """Validate that the port can be used in a trunk.

        :param parent_port: True if the port is intended for use
                            as parent in a trunk.
        """
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

        if parent_port:
            # if the port is being used as a parent in a trunk, check if
            # it can be trunked, i.e. if it is already associated to physical
            # resources (namely it is bound). Bound ports may be used as
            # trunk parents, but that depends on the underlying driver in
            # charge.
            if not self.can_be_trunked(context):
                raise trunk_exc.ParentPortInUse(port_id=self.port_id)
        else:
            # if the port is being used as subport in a trunk, check if it is a
            # port that is not actively used for other purposes, e.g. a router
            # port, compute port, DHCP port etc. We have no clue what the side
            # effects of connecting the port to a trunk would be, and it is
            # better to err on the side of caution and prevent the operation.
            self.check_not_in_use(context)

        return self.port_id

    def is_bound(self, context):
        """Return true if the port is bound, false otherwise."""
        # Validate that the given port_id does not have a port binding.
        core_plugin = directory.get_plugin()
        self._port = core_plugin.get_port(context, self.port_id)
        return bool(self._port.get(portbindings.HOST_ID))

    def can_be_trunked(self, context):
        """"Return true if a port can be trunked."""
        if not self.is_bound(context):
            # An unbound port can be trunked, always.
            return True

        trunk_plugin = directory.get_plugin('trunk')
        vif_type = self._port.get(portbindings.VIF_TYPE)
        binding_host = self._port.get(portbindings.HOST_ID)

        # Determine the driver that will be in charge of the trunk: this
        # can be determined based on the vif type, whether or not the
        # driver is agent-based, and whether the host is running the agent
        # associated to the driver itself.
        host_agent_types = utils.get_agent_types_by_host(context, binding_host)
        drivers = [
            driver for driver in trunk_plugin.registered_drivers
            if utils.is_driver_compatible(
                context, driver, vif_type, host_agent_types)
        ]
        if len(drivers) > 1:
            raise trunk_exc.TrunkPluginDriverConflict()
        elif len(drivers) == 1:
            return drivers[0].can_trunk_bound_port
        else:
            return False

    def check_not_in_use(self, context):
        """Raises PortInUse for ports assigned for device purposes."""
        core_plugin = directory.get_plugin()
        self._port = core_plugin.get_port(context, self.port_id)
        # NOTE(armax): the trunk extension itself does not make use of the
        # device_id field, because it has no reason to. If need be, this
        # check can be altered to accommodate the change in logic.
        if self._port['device_id']:
            raise n_exc.PortInUse(net_id=self._port['network_id'],
                                  port_id=self._port['id'],
                                  device_id=self._port['device_id'])


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
            msg = validators.validate_subports(self.subports)
            if msg:
                raise n_exc.InvalidInput(error_message=msg)
        if trunk_validation:
            trunk_port_mtu = self._get_port_mtu(context, self.trunk_port_id)
            return [self._validate(context, s, trunk_port_mtu)
                    for s in self.subports]
        else:
            return self.subports

    def _get_port_mtu(self, context, port_id):
        """
        Return MTU for the network where the given port belongs to.
        If the network or port cannot be obtained, or if MTU is not defined,
        returns None.
        """
        core_plugin = directory.get_plugin()

        if not n_utils.is_extension_supported(core_plugin, 'net-mtu'):
            return

        try:
            port = core_plugin.get_port(context, port_id)
            net = core_plugin.get_network(context, port['network_id'])
        except (n_exc.PortNotFound, n_exc.NetworkNotFound):
            # A concurrent request might have made the port or network
            # disappear; though during DB insertion, the subport request
            # will fail on integrity constraint, it is safer to return
            # a None MTU here.
            return

        return net[api.MTU]

    def _validate(self, context, subport, trunk_port_mtu):
        # Check that the subport doesn't reference the same port_id as a
        # trunk we may be in the middle of trying to create, in other words
        # make the validation idiot proof.
        if subport['port_id'] == self.trunk_port_id:
            raise trunk_exc.ParentPortInUse(port_id=subport['port_id'])

        # Check MTU sanity - subport MTU must not exceed trunk MTU.
        # If for whatever reason trunk_port_mtu is not available,
        # the MTU sanity check cannot be enforced.
        if trunk_port_mtu:
            port_mtu = self._get_port_mtu(context, subport['port_id'])
            if port_mtu and port_mtu > trunk_port_mtu:
                raise trunk_exc.SubPortMtuGreaterThanTrunkPortMtu(
                    port_id=subport['port_id'],
                    port_mtu=port_mtu,
                    trunk_id=self.trunk_port_id,
                    trunk_mtu=trunk_port_mtu
                )

        # If the segmentation details are missing, we will need to
        # figure out defaults when the time comes to support Ironic.
        # We can reasonably expect segmentation details to be provided
        # in all other cases for now.
        try:
            segmentation_type = subport["segmentation_type"]
            segmentation_id = (
                converters.convert_to_int(subport["segmentation_id"]))
        except KeyError:
            msg = _("Invalid subport details '%s': missing segmentation "
                    "information. Must specify both segmentation_id and "
                    "segmentation_type") % subport
            raise n_exc.InvalidInput(error_message=msg)
        except n_exc.InvalidInput:
            msg = _("Invalid subport details: segmentation_id '%s' is "
                    "not an integer") % subport["segmentation_id"]
            raise n_exc.InvalidInput(error_message=msg)

        if segmentation_type not in self._segmentation_types:
            msg = _("Unknown segmentation_type '%s'") % segmentation_type
            raise n_exc.InvalidInput(error_message=msg)

        if not self._segmentation_types[segmentation_type](segmentation_id):
            msg = _("Segmentation ID '%s' is not in range") % segmentation_id
            raise n_exc.InvalidInput(error_message=msg)

        # Check if the subport is already participating in an active trunk
        trunk_validator = TrunkPortValidator(subport['port_id'])
        trunk_validator.validate(context, parent_port=False)
        return subport
