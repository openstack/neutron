# Copyright (c) 2015 Taturiello Consulting, Meh.
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

from neutron.pecan_wsgi.controllers import resource
from neutron.pecan_wsgi.controllers import utils as controller_utils


def get_controller(state):
    if (state.arguments and state.arguments.args and
            isinstance(state.arguments.args[0],
                       controller_utils.NeutronPecanController)):
        controller = state.arguments.args[0]
        return controller


def is_member_action(controller):
    return isinstance(controller,
                      resource.MemberActionController)
