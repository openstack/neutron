# Copyright (c) 2015 Mirantis, Inc.
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

from neutron_lib import constants as const
from oslo_log import log as logging
from oslo_policy import policy as oslo_policy
from oslo_utils import excutils
from pecan import hooks
import webob

from neutron._i18n import _
from neutron.extensions import quotasv2
from neutron import manager
from neutron.pecan_wsgi import constants as pecan_constants
from neutron.pecan_wsgi.controllers import quota
from neutron.pecan_wsgi.hooks import utils
from neutron import policy

LOG = logging.getLogger(__name__)


def _custom_getter(resource, resource_id):
    """Helper function to retrieve resources not served by any plugin."""
    if resource == quotasv2.RESOURCE_NAME:
        return quota.get_tenant_quotas(resource_id)[quotasv2.RESOURCE_NAME]


def fetch_resource(method, neutron_context, controller,
                   collection, resource, resource_id,
                   parent_id=None):
    field_list = []
    if method == 'PUT':
        attrs = controller.resource_info
        if not attrs:
            # this isn't a request for a normal resource. it could be
            # an action like removing a network from a dhcp agent.
            # return None and assume the custom controller for this will
            # handle the necessary logic.
            return
        field_list = [name for (name, value) in attrs.items()
                      if (value.get('required_by_policy') or
                          value.get('primary_key') or 'default' not in value)]
    plugin = manager.NeutronManager.get_plugin_for_resource(collection)
    if plugin:
        if utils.is_member_action(controller):
            getter = controller.parent_controller.plugin_shower
        else:
            getter = controller.plugin_shower
        getter_args = [neutron_context, resource_id]
        if parent_id:
            getter_args.append(parent_id)
        return getter(*getter_args, fields=field_list)
    # Some legit resources, like quota, do not have a plugin yet. Retrieving
    # the original object is nevertheless important for policy checks.
    return _custom_getter(resource, resource_id)


class PolicyHook(hooks.PecanHook):
    priority = 140

    def before(self, state):
        # This hook should be run only for PUT,POST and DELETE methods and for
        # requests targeting a neutron resource
        resources = state.request.context.get('resources', [])
        if state.request.method not in ('POST', 'PUT', 'DELETE'):
            return
        # As this routine will likely alter the resources, do a shallow copy
        resources_copy = resources[:]
        neutron_context = state.request.context.get('neutron_context')
        resource = state.request.context.get('resource')
        # If there is no resource for this request, don't bother running authZ
        # policies
        if not resource:
            return
        controller = utils.get_controller(state)
        if not controller or utils.is_member_action(controller):
            return
        collection = state.request.context.get('collection')
        needs_prefetch = state.request.method in ('PUT', 'DELETE')

        action = controller.plugin_handlers[
            pecan_constants.ACTION_MAP[state.request.method]]

        # NOTE(salv-orlando): As bulk updates are not supported, in case of PUT
        # requests there will be only a single item to process, and its
        # identifier would have been already retrieved by the lookup process;
        # in the case of DELETE requests there won't be any item to process in
        # the request body
        original_resources = []
        if needs_prefetch:
            try:
                item = resources_copy.pop()
            except IndexError:
                # Ops... this was a delete after all!
                item = {}
            resource_id = state.request.context.get('resource_id')
            parent_id = state.request.context.get('parent_id')
            method = state.request.method
            resource_obj = fetch_resource(method, neutron_context, controller,
                                          collection, resource, resource_id,
                                          parent_id=parent_id)
            if resource_obj:
                original_resources.append(resource_obj)
                obj = resource_obj | item
                obj[const.ATTRIBUTES_TO_UPDATE] = list(item)
                # Put back the item in the list so that policies could be
                # enforced
                resources_copy.append(obj)
        # TODO(salv-orlando): as other hooks might need to prefetch resources,
        # store them in the request context. However, this should be done in a
        # separate hook which is conveniently called before all other hooks
        state.request.context['original_resources'] = original_resources
        for item in resources_copy:
            try:
                policy.enforce(
                    neutron_context, action, item,
                    pluralized=collection)
            except (oslo_policy.PolicyNotAuthorized, oslo_policy.InvalidScope):
                with excutils.save_and_reraise_exception() as ctxt:
                    controller = utils.get_controller(state)
                    # If a tenant is modifying it's own object, it's safe to
                    # return a 403. Otherwise, pretend that it doesn't exist
                    # to avoid giving away information.
                    # It is also safe to return 403 if it's POST (CREATE)
                    # request.
                    s_action = controller.plugin_handlers[controller.SHOW]
                    c_action = controller.plugin_handlers[controller.CREATE]
                    if (action != c_action and
                            not policy.check(neutron_context, s_action, item,
                                             pluralized=collection)):
                        ctxt.reraise = False
                msg = _('The resource could not be found.')
                raise webob.exc.HTTPNotFound(msg)

    def after(self, state):
        neutron_context = state.request.context.get('neutron_context')
        resource = state.request.context.get('resource')
        collection = state.request.context.get('collection')
        controller = utils.get_controller(state)
        if not resource:
            # can't filter a resource we don't recognize
            return
        # NOTE(kevinbenton): extension listing isn't controlled by policy
        if resource == 'extension':
            return
        try:
            data = state.response.json
        except ValueError:
            return
        if state.request.method not in pecan_constants.ACTION_MAP:
            return
        if not data or (resource not in data and collection not in data):
            return
        is_single = resource in data
        action_type = pecan_constants.ACTION_MAP[state.request.method]
        if action_type == 'get':
            action = controller.plugin_handlers[controller.SHOW]
        else:
            action = controller.plugin_handlers[action_type]
        key = resource if is_single else collection
        to_process = [data[resource]] if is_single else data[collection]
        # in the single case, we enforce which raises on violation
        # in the plural case, we just check so violating items are hidden
        policy_method = policy.enforce if is_single else policy.check
        try:
            resp = [self._get_filtered_item(state.request, controller,
                                            resource, collection, item)
                    for item in to_process
                    if (state.request.method != 'GET' or
                        policy_method(neutron_context, action, item,
                                      pluralized=collection))]
        except (oslo_policy.PolicyNotAuthorized, oslo_policy.InvalidScope):
            # This exception must be explicitly caught as the exception
            # translation hook won't be called if an error occurs in the
            # 'after' handler.  Instead of raising an HTTPNotFound exception,
            # we have to set the status_code here to prevent the catch_errors
            # middleware from turning this into a 500.
            state.response.status_code = 404
            return

        if is_single:
            resp = resp[0]
        state.response.json = {key: resp}

    def _get_filtered_item(self, request, controller, resource, collection,
                           data):
        neutron_context = request.context.get('neutron_context')
        to_exclude = self._exclude_attributes_by_policy(
            neutron_context, controller, resource, collection, data)
        return self._filter_attributes(request, data, to_exclude)

    def _filter_attributes(self, request, data, fields_to_strip):
        # This routine will remove the fields that were requested to the
        # plugin for policy evaluation but were not specified in the
        # API request
        return dict(item for item in data.items()
                    if item[0] not in fields_to_strip)

    def _exclude_attributes_by_policy(self, context, controller, resource,
                                      collection, data):
        """Identifies attributes to exclude according to authZ policies.

        Return a list of attribute names which should be stripped from the
        response returned to the user because the user is not authorized
        to see them.
        """
        attributes_to_exclude = []
        for attr_name in list(data):
            # TODO(amotoki): All attribute maps have tenant_id and
            # it determines excluded attributes based on tenant_id.
            # We need to migrate tenant_id to project_id later
            # as attr_info is referred to in various places and we need
            # to check all logs carefully.
            if attr_name == 'project_id':
                continue
            attr_data = controller.resource_info.get(attr_name)
            if attr_data and attr_data['is_visible']:
                if policy.check(
                        context,
                        # NOTE(kevinbenton): this used to reference a
                        # _plugin_handlers dict, why?
                        f'get_{resource}:{attr_name}',
                        data,
                        might_not_exist=True,
                        pluralized=collection):
                    # this attribute is visible, check next one
                    continue
            # if the code reaches this point then either the policy check
            # failed or the attribute was not visible in the first place
            attributes_to_exclude.append(attr_name)
            # TODO(amotoki): As mentioned in the above TODO,
            # we treat project_id and tenant_id equivalently.
            # This should be migrated to project_id later.
            if attr_name == 'tenant_id':
                attributes_to_exclude.append('project_id')
        if attributes_to_exclude:
            LOG.debug("Attributes excluded by policy engine: %s",
                      attributes_to_exclude)
        return attributes_to_exclude
