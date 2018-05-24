# Copyright 2016 Hewlett Packard Enterprise Development, LP
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
from neutron_lib import exceptions


class SegmentNotFound(exceptions.NotFound):
    message = _("Segment %(segment_id)s could not be found.")


class NoUpdateSubnetWhenMultipleSegmentsOnNetwork(
    exceptions.BadRequest):
    message = _("The network '%(network_id)s' has multiple segments, it is "
                "only possible to associate an existing subnet with a segment "
                "on networks with a single segment.")


class SubnetsNotAllAssociatedWithSegments(exceptions.BadRequest):
    message = _("All of the subnets on network '%(network_id)s' must either "
                "all be associated with segments or all not associated with "
                "any segment.")


class SubnetCantAssociateToDynamicSegment(exceptions.BadRequest):
    message = _("A subnet cannot be associated with a dynamic segment.")


class SubnetSegmentAssociationChangeNotAllowed(exceptions.BadRequest):
    message = _("A subnet that is already associated with a segment cannot "
                "have its segment association changed.")


class NetworkIdsDontMatch(exceptions.BadRequest):
    message = _("The subnet's network id, '%(subnet_network)s', doesn't match "
                "the network_id of segment '%(segment_id)s'")


class HostConnectedToMultipleSegments(exceptions.Conflict):
    message = _("Host %(host)s is connected to multiple segments on routed "
                "provider network '%(network_id)s'.  It should be connected "
                "to one.")


class HostNotConnectedToAnySegment(exceptions.Conflict):
    message = _("Host %(host)s is not connected to any segments on routed "
                "provider network '%(network_id)s'.  It should be connected "
                "to one.")


class HostNotCompatibleWithFixedIps(exceptions.Conflict):
    message = _("Host %(host)s is not connected to a segment where the "
                "existing fixed_ips on port %(port_id)s will function given "
                "the routed network topology.")


class SegmentInUse(exceptions.InUse):
    message = _("Segment '%(segment_id)s' cannot be deleted: %(reason)s.")
