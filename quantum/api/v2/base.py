# Copyright (c) 2012 OpenStack, LLC.
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

import logging

import webob.exc

from quantum.api.v2 import resource as wsgi_resource
from quantum.api.v2 import views
from quantum.common import exceptions
from quantum.common import utils
from quantum import policy

LOG = logging.getLogger(__name__)
XML_NS_V20 = 'http://openstack.org/quantum/api/v2.0'

FAULT_MAP = {exceptions.NotFound: webob.exc.HTTPNotFound,
             exceptions.InUse: webob.exc.HTTPConflict,
             exceptions.MacAddressGenerationFailure:
             webob.exc.HTTPServiceUnavailable,
             exceptions.StateInvalid: webob.exc.HTTPBadRequest}


def fields(request):
    """
    Extracts the list of fields to return
    """
    return [v for v in request.GET.getall('fields') if v]


def filters(request):
    """
    Extracts the filters from the request string

    Returns a dict of lists for the filters:

    check=a&check=b&name=Bob&verbose=True&verbose=other

    becomes

    {'check': [u'a', u'b'], 'name': [u'Bob']}
    """
    res = {}
    for key in set(request.GET):
        if key in ('verbose', 'fields'):
            continue

        values = [v for v in request.GET.getall(key) if v]
        if values:
            res[key] = values
    return res


def verbose(request):
    """
    Determines the verbose fields for a request

    Returns a list of items that are requested to be verbose:

    check=a&check=b&name=Bob&verbose=True&verbose=other

    returns

    [True]

    and

    check=a&check=b&name=Bob&verbose=other

    returns

    ['other']

    """
    verbose = [utils.boolize(v) for v in request.GET.getall('verbose') if v]

    # NOTE(jkoelker) verbose=<bool> trumps all other verbose settings
    if True in verbose:
        return True
    elif False in verbose:
        return False

    return verbose


class Controller(object):
    def __init__(self, plugin, collection, resource, attr_info):
        self._plugin = plugin
        self._collection = collection
        self._resource = resource
        self._attr_info = attr_info
        self._view = getattr(views, self._resource)

    def _items(self, request, do_authz=False):
        """Retrieves and formats a list of elements of the requested entity"""
        kwargs = {'filters': filters(request),
                  'verbose': verbose(request),
                  'fields': fields(request)}

        obj_getter = getattr(self._plugin, "get_%s" % self._collection)
        obj_list = obj_getter(request.context, **kwargs)

        # Check authz
        if do_authz:
            # Omit items from list that should not be visible
            obj_list = [obj for obj in obj_list
                        if policy.check(request.context,
                                        "get_%s" % self._resource,
                                        obj)]

        return {self._collection: [self._view(obj) for obj in obj_list]}

    def _item(self, request, id, do_authz=False):
        """Retrieves and formats a single element of the requested entity"""
        kwargs = {'verbose': verbose(request),
                  'fields': fields(request)}
        action = "get_%s" % self._resource
        obj_getter = getattr(self._plugin, action)
        obj = obj_getter(request.context, id, **kwargs)

        # Check authz
        if do_authz:
            policy.enforce(request.context, action, obj)

        return {self._resource: self._view(obj)}

    def index(self, request):
        """Returns a list of the requested entity"""
        return self._items(request, True)

    def show(self, request, id):
        """Returns detailed information about the requested entity"""
        try:
            return self._item(request, id, True)
        except exceptions.PolicyNotAuthorized:
            # To avoid giving away information, pretend that it
            # doesn't exist
            raise webob.exc.HTTPNotFound()

    def create(self, request, body=None):
        """Creates a new instance of the requested entity"""

        body = self._prepare_request_body(request.context, body, True,
                                          allow_bulk=True)

        action = "create_%s" % self._resource

        # Check authz
        try:
            if self._collection in body:
                # Have to account for bulk create
                for item in body[self._collection]:
                    policy.enforce(request.context, action,
                                   item[self._resource])
            else:
                policy.enforce(request.context, action, body[self._resource])
        except exceptions.PolicyNotAuthorized:
            raise webob.exc.HTTPForbidden()

        obj_creator = getattr(self._plugin, action)
        kwargs = {self._resource: body}
        obj = obj_creator(request.context, **kwargs)
        return {self._resource: self._view(obj)}

    def delete(self, request, id):
        """Deletes the specified entity"""
        action = "delete_%s" % self._resource

        # Check authz
        obj = self._item(request, id)
        try:
            policy.enforce(request.context, action, obj)
        except exceptions.PolicyNotAuthorized:
            # To avoid giving away information, pretend that it
            # doesn't exist
            raise webob.exc.HTTPNotFound()

        obj_deleter = getattr(self._plugin, action)
        obj_deleter(request.context, id)

    def update(self, request, id, body=None):
        """Updates the specified entity's attributes"""
        body = self._prepare_request_body(request.context, body, False)
        action = "update_%s" % self._resource

        # Check authz
        orig_obj = self._item(request, id)
        try:
            policy.enforce(request.context, action, orig_obj)
        except exceptions.PolicyNotAuthorized:
            # To avoid giving away information, pretend that it
            # doesn't exist
            raise webob.exc.HTTPNotFound()

        obj_updater = getattr(self._plugin, action)
        kwargs = {self._resource: body}
        obj = obj_updater(request.context, id, **kwargs)
        return {self._resource: self._view(obj)}

    def _populate_tenant_id(self, context, res_dict, is_create):

        if self._resource not in ['network', 'port']:
            return

        if (('tenant_id' in res_dict and
             res_dict['tenant_id'] != context.tenant_id and
             not context.is_admin)):
            msg = _("Specifying 'tenant_id' other than authenticated"
                    "tenant in request requires admin privileges")
            raise webob.exc.HTTPBadRequest(msg)

        if is_create and 'tenant_id' not in res_dict:
            if context.tenant_id:
                res_dict['tenant_id'] = context.tenant_id
            else:
                msg = _("Running without keystyone AuthN requires "
                        " that tenant_id is specified")
                raise webob.exc.HTTPBadRequest(msg)

    def _prepare_request_body(self, context, body, is_create,
                              allow_bulk=False):
        """ verifies required attributes are in request body, and that
            an attribute is only specified if it is allowed for the given
            operation (create/update).
            Attribute with default values are considered to be
            optional.

            body argument must be the deserialized body
        """
        if not body:
            raise webob.exc.HTTPBadRequest(_("Resource body required"))

        body = body or {self._resource: {}}

        if self._collection in body and allow_bulk:
            bulk_body = [self._prepare_request_body(context,
                                                    {self._resource: b},
                                                    is_create)
                         if self._resource not in b
                         else self._prepare_request_body(context, b, is_create)
                         for b in body[self._collection]]

            if not bulk_body:
                raise webob.exc.HTTPBadRequest(_("Resources required"))

            return {self._collection: bulk_body}

        elif self._collection in body and not allow_bulk:
            raise webob.exc.HTTPBadRequest("Bulk operation not supported")

        res_dict = body.get(self._resource)
        if res_dict is None:
            msg = _("Unable to find '%s' in request body") % self._resource
            raise webob.exc.HTTPBadRequest(msg)

        self._populate_tenant_id(context, res_dict, is_create)

        if is_create:  # POST
            for attr, attr_vals in self._attr_info.iteritems():
                is_required = ('default' not in attr_vals and
                               attr_vals['allow_post'])
                if is_required and attr not in res_dict:
                    msg = _("Failed to parse request. Required "
                            " attribute '%s' not specified") % attr
                    raise webob.exc.HTTPUnprocessableEntity(msg)

                if not attr_vals['allow_post'] and attr in res_dict:
                    msg = _("Attribute '%s' not allowed in POST" % attr)
                    raise webob.exc.HTTPUnprocessableEntity(msg)

                if attr_vals['allow_post']:
                    res_dict[attr] = res_dict.get(attr,
                                                  attr_vals.get('default'))

        else:  # PUT
            for attr, attr_vals in self._attr_info.iteritems():
                if attr in res_dict and not attr_vals['allow_put']:
                    msg = _("Cannot update read-only attribute %s") % attr
                    raise webob.exc.HTTPUnprocessableEntity(msg)

        return body


def create_resource(collection, resource, plugin, params):
    controller = Controller(plugin, collection, resource, params)

    # NOTE(jkoelker) To anyone wishing to add "proper" xml support
    #                this is where you do it
    serializers = {}
    #    'application/xml': wsgi.XMLDictSerializer(metadata, XML_NS_V20),

    deserializers = {}
    #    'application/xml': wsgi.XMLDeserializer(metadata),

    return wsgi_resource.Resource(controller, FAULT_MAP, deserializers,
                                  serializers)
