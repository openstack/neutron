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

from neutron._i18n import _
from neutron_lib import exceptions as n_exc


class TrunkPortInUse(n_exc.InUse):
    message = _("Port %(port_id)s is in use by another trunk.")


class TrunkNotFound(n_exc.NotFound):
    message = _("Trunk %(trunk_id)s could not be found.")


class SubPortNotFound(n_exc.NotFound):
    message = _("SubPort %(port_id)s on trunk %(trunk_id)s "
                "could not be found.")


class DuplicateSubPort(n_exc.InUse):
    message = _("segmentation_type %(segmentation_type)s and segmentation_id "
                "%(segmentation_id)s already in use on trunk %(trunk_id)s.")


class ParentPortInUse(n_exc.InUse):
    message = _("Port %(port_id)s is currently in use and is not "
                "eligible for use as a parent port.")


class SubPortMtuGreaterThanTrunkPortMtu(n_exc.Conflict):
    message = _("MTU %(port_mtu)s of subport %(port_id)s cannot be greater "
                "than MTU %(trunk_mtu)s of trunk %(trunk_id)s.")


class PortInUseAsTrunkParent(n_exc.InUse):
    message = _("Port %(port_id)s is currently a parent port "
                "for trunk %(trunk_id)s.")


class PortInUseAsSubPort(n_exc.InUse):
    message = _("Port %(port_id)s is currently a subport for "
                "trunk %(trunk_id)s.")


class TrunkInUse(n_exc.InUse):
    message = _("Trunk %(trunk_id)s is currently in use.")


class TrunkDisabled(n_exc.Conflict):
    message = _("Trunk %(trunk_id)s is currently disabled.")


class TrunkInErrorState(n_exc.Conflict):
    message = _("Trunk %(trunk_id)s is in error state. Attempt "
                "to resolve the error condition before proceeding.")


class IncompatibleTrunkPluginConfiguration(n_exc.NeutronException):
    message = _("Cannot load trunk plugin: no compatible core plugin "
                "configuration is found.")


class IncompatibleDriverSegmentationTypes(n_exc.NeutronException):
    message = _("Cannot load trunk plugin: no compatible segmentation "
                "type configuration can be found amongst list of loaded "
                "drivers.")


class SegmentationTypeValidatorNotFound(n_exc.NotFound):
    message = _("Validator not found for segmentation type %(seg_type)s. "
                "It must be registered before the plugin init can "
                "proceed.")


class TrunkPluginDriverConflict(n_exc.Conflict):
    message = _("A misconfiguration in the environment prevents the "
                "operation from completing, please, contact the admin.")


class SubPortBindingError(n_exc.NeutronException):
    message = _("Failed to set port binding for port %(port_id)s on trunk "
                "%(trunk_id)s.")
