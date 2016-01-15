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

from neutron._i18n import _LE
from oslo_log import log
import pecan
from pecan import request

from neutron import manager
from neutron.pecan_wsgi.controllers import resource
from neutron.pecan_wsgi.controllers import utils

LOG = log.getLogger(__name__)


class RouterController(resource.ItemController):
    """Customize ResourceController for member actions"""

    ### Pecan generic controllers don't work very well with inheritance

    @utils.expose(generic=True)
    def index(self, *args, **kwargs):
        return super(RouterController, self).index(*args, **kwargs)

    @utils.when(index, method='HEAD')
    @utils.when(index, method='POST')
    @utils.when(index, method='PATCH')
    def not_supported(self):
        return super(RouterController, self).not_supported()

    @utils.when(index, method='PUT')
    def put(self, *args, **kwargs):
        return super(RouterController, self).put(*args, **kwargs)

    @utils.when(index, method='DELETE')
    def delete(self):
        return super(RouterController, self).delete()

    @utils.expose()
    def _lookup(self, member_action, *remainder):
        # This check is mainly for the l3-agents resource.  If there isn't
        # a controller for it then we'll just assume its a member action.
        controller = manager.NeutronManager.get_controller_for_resource(
            member_action)
        if not controller:
            controller = RouterMemberActionController(
                self.resource, self.item, member_action)
        return controller, remainder


class RoutersController(resource.CollectionsController):

    item_controller_class = RouterController

    def __init__(self):
        super(RoutersController, self).__init__('routers', 'router')


class RouterMemberActionController(resource.ItemController):

    def __init__(self, resource, item, member_action):
        super(RouterMemberActionController, self).__init__(resource, item)
        self.member_action = member_action

    @utils.expose(generic=True)
    def index(self, *args, **kwargs):
        pecan.abort(405)

    @utils.when(index, method='HEAD')
    @utils.when(index, method='POST')
    @utils.when(index, method='PATCH')
    def not_supported(self):
        return super(RouterMemberActionController, self).not_supported()

    @utils.when(index, method='PUT')
    def put(self, *args, **kwargs):
        neutron_context = request.context['neutron_context']
        LOG.debug("Processing member action %(action)s for resource "
                  "%(resource)s identified by %(item)s",
                  {'action': self.member_action,
                   'resource': self.resource,
                   'item': self.item})
        # NOTE(salv-orlando): The following simply verify that the plugin
        # has a method for a given action. It therefore enables plugins to
        # implement actions which are not part of the API specification.
        # Unfortunately the API extension descriptor does not do a good job
        # of sanctioning which actions are available on a given resource.
        # TODO(salv-orlando): prevent plugins from implementing actions
        # which are not part of the Neutron API spec
        try:
            member_action_method = getattr(self.plugin, self.member_action)
            return member_action_method(neutron_context, self.item,
                                        request.context['request_data'])
        except AttributeError:
            LOG.error(_LE("Action %(action)s is not defined on resource "
                          "%(resource)s"),
                      {'action': self.member_action,
                       'resource': self.resource})
            pecan.abort(404)
