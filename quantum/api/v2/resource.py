# Copyright 2012 OpenStack LLC.
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
import logging

import webob
import webob.dec
import webob.exc

from quantum.common import exceptions
from quantum import context
from quantum.openstack.common import jsonutils as json
from quantum import wsgi


LOG = logging.getLogger(__name__)


class Request(webob.Request):
    """Add some Openstack API-specific logic to the base webob.Request."""

    def best_match_content_type(self):
        supported = ('application/json', )
        return self.accept.best_match(supported,
                                      default_match='application/json')

    @property
    def context(self):
        #Eventually the Auth[NZ] code will supply this. (mdragon)
        #when that happens this if block should raise instead.
        if 'quantum.context' not in self.environ:
            self.environ['quantum.context'] = context.get_admin_context()
        return self.environ['quantum.context']


def Resource(controller, faults=None, deserializers=None, serializers=None):
    """Represents an API entity resource and the associated serialization and
    deserialization logic
    """
    default_deserializers = {'application/xml': wsgi.XMLDeserializer(),
                             'application/json': lambda x: json.loads(x)}
    default_serializers = {'application/xml': wsgi.XMLDictSerializer(),
                           'application/json': lambda x: json.dumps(x)}
    format_types = {'xml': 'application/xml',
                    'json': 'application/json'}
    action_status = dict(create=201, delete=204)

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
        deserializer = deserializers.get(content_type)
        serializer = serializers.get(content_type)

        try:
            if request.body:
                args['body'] = deserializer(request.body)

            method = getattr(controller, action)

            result = method(request=request, **args)
        except exceptions.QuantumException as e:
            LOG.exception('%s failed' % action)
            body = serializer({'QuantumError': str(e)})
            kwargs = {'body': body, 'content_type': content_type}
            for fault in faults:
                if isinstance(e, fault):
                    raise faults[fault](**kwargs)
            raise webob.exc.HTTPInternalServerError(**kwargs)
        except webob.exc.HTTPException as e:
            LOG.exception('%s failed' % action)
            e.body = serializer({'QuantumError': str(e)})
            e.content_type = content_type
            raise
        except Exception as e:
            # NOTE(jkoelker) Everyting else is 500
            LOG.exception('%s failed' % action)
            # Do not expose details of 500 error to clients.
            msg = _('Request Failed: internal server error while '
                    'processing your request.')
            body = serializer({'QuantumError': msg})
            kwargs = {'body': body, 'content_type': content_type}
            raise webob.exc.HTTPInternalServerError(**kwargs)

        status = action_status.get(action, 200)
        body = serializer(result)
        # NOTE(jkoelker) Comply with RFC2616 section 9.7
        if status == 204:
            content_type = ''
            body = None

        return webob.Response(request=request, status=status,
                              content_type=content_type,
                              body=body)
    return resource
