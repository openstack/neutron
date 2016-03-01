# Copyright 2016 Huawei Technologies India Pvt. Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron._i18n import _
from neutron.common import exceptions as n_exc


# BGP Driver Exceptions
class BgpSpeakerNotAdded(n_exc.BadRequest):
    message = _("BGP Speaker for local_as=%(local_as)s with "
                "router_id=%(rtid)s not added yet.")


class BgpSpeakerMaxScheduled(n_exc.BadRequest):
    message = _("Already hosting maximum number of BGP Speakers. "
                "Allowed scheduled count=%(count)d")


class BgpSpeakerAlreadyScheduled(n_exc.Conflict):
    message = _("Already hosting BGP Speaker for local_as=%(current_as)d with "
                "router_id=%(rtid)s.")


class BgpPeerNotAdded(n_exc.BadRequest):
    message = _("BGP Peer %(peer_ip)s for remote_as=%(remote_as)s, running "
                "for BGP Speaker %(speaker_as)d not added yet.")


class RouteNotAdvertised(n_exc.BadRequest):
    message = _("Route %(cidr)s not advertised for BGP Speaker "
                "%(speaker_as)d.")


class InvalidParamType(n_exc.NeutronException):
    message = _("Parameter %(param)s must be of %(param_type)s type.")


class InvalidParamRange(n_exc.NeutronException):
    message = _("%(param)s must be in %(range)s range.")


class InvaildAuthType(n_exc.BadRequest):
    message = _("Authentication type not supported. Requested "
                "type=%(auth_type)s.")


class PasswordNotSpecified(n_exc.BadRequest):
    message = _("Password not specified for authentication "
                "type=%(auth_type)s.")
