# Copyright 2012 OpenStack Foundation.
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

"""
Utility methods for working with WSGI servers redux
"""

from oslo_log import log as logging
import webob.dec
import webob.exc

from neutron.api import api_common
from neutron.common import utils
from neutron import wsgi


LOG = logging.getLogger(__name__)


class Request(wsgi.Request):
    pass


def Resource(controller, faults=None, deserializers=None, serializers=None,
             action_status=None):
    """Represents an API entity resource and the associated serialization and
    deserialization logic
    """
    default_deserializers = {'application/json': wsgi.JSONDeserializer()}
    default_serializers = {'application/json': wsgi.JSONDictSerializer()}
    format_types = {'json': 'application/json'}
    action_status = action_status or dict(create=201, delete=204)

    default_deserializers.update(deserializers or {})
    default_serializers.update(serializers or {})

    deserializers = default_deserializers
    serializers = default_serializers
    faults = faults or {}

    @webob.dec.wsgify(RequestClass=Request)
    def resource(request):
        route_args = request.environ.get('wsgiorg.routing_args')
        if route_args:
            args = route_args[1].copy()
        else:
            args = {}

        # NOTE(jkoelker) by now the controller is already found, remove
        #                it from the args if it is in the matchdict
        args.pop('controller', None)
        fmt = args.pop('format', None)
        action = args.pop('action', None)
        content_type = format_types.get(fmt,
                                        request.best_match_content_type())
        language = request.best_match_language()
        deserializer = deserializers.get(content_type)
        serializer = serializers.get(content_type)

        try:
            if request.body:
                args['body'] = deserializer.deserialize(request.body)['body']

            # Routes library is dumb and cuts off everything after last dot (.)
            # as format. At the same time, it doesn't enforce format suffix,
            # which combined makes it impossible to pass a 'id' with dots
            # included (the last section after the last dot is lost). This is
            # important for some API extensions like tags where the id is
            # really a tag name that can contain special characters.
            #
            # To work around the Routes behaviour, we will attach the suffix
            # back to id if it's not one of supported formats (atm json only).
            # This of course won't work for the corner case of a tag name that
            # actually ends with '.json', but there seems to be no better way
            # to tackle it without breaking API backwards compatibility.
            if fmt is not None and fmt not in format_types:
                args['id'] = '.'.join([args['id'], fmt])

            revision_number = api_common.check_request_for_revision_constraint(
                request)
            if revision_number is not None:
                request.context.set_transaction_constraint(
                    controller._collection, args['id'], revision_number)

            method = getattr(controller, action)
            result = method(request=request, **args)
        except Exception as e:
            mapped_exc = api_common.convert_exception_to_http_exc(e, faults,
                                                                  language)
            if hasattr(mapped_exc, 'code') and 400 <= mapped_exc.code < 500:
                LOG.info('%(action)s failed (client error): %(exc)s',
                         {'action': action, 'exc': mapped_exc})
            else:
                LOG.exception('%(action)s failed: %(details)s',
                              {
                                  'action': action,
                                  'details': utils.extract_exc_details(e),
                              }
                              )
            raise mapped_exc

        status = action_status.get(action, 200)
        body = serializer.serialize(result)
        # NOTE(jkoelker) Comply with RFC2616 section 9.7
        if status == 204:
            content_type = ''
            body = None

        return webob.Response(request=request, status=status,
                              content_type=content_type,
                              body=body)
    # NOTE(blogan): this is something that is needed for the transition to
    # pecan.  This will allow the pecan code to have a handle on the controller
    # for an extension so it can reuse the code instead of forcing every
    # extension to rewrite the code for use with pecan.
    setattr(resource, 'controller', controller)
    setattr(resource, 'action_status', action_status)
    return resource
