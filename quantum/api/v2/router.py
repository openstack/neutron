# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import urlparse

import routes as routes_mapper
import webob
import webob.dec
import webob.exc

from quantum import manager
from quantum import wsgi
from quantum.api.v2 import base


LOG = logging.getLogger(__name__)
HEX_ELEM = '[0-9A-Fa-f]'
UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{12}'])
COLLECTION_ACTIONS = ['index', 'create']
MEMBER_ACTIONS = ['show', 'update', 'delete']
REQUIREMENTS = {'id': UUID_PATTERN, 'format': 'xml|json'}


RESOURCE_PARAM_MAP = {
    'networks': [
        {'attr': 'name'},
    ],
    'ports': [
        {'attr': 'state', 'default': 'DOWN'},
    ],
    'subnets': [
        {'attr': 'prefix'},
        {'attr': 'network_id'},
    ]
}


class Index(wsgi.Application):
    def __init__(self, resources):
        self.resources = resources

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        metadata = {'application/xml': {
                        'attributes': {
                            'resource': ['name', 'collection'],
                            'link': ['href', 'rel'],
                           }
                       }
                   }

        layout = []
        for name, collection in self.resources.iteritems():
            href = urlparse.urljoin(req.path_url, collection)
            resource = {'name': name,
                        'collection': collection,
                        'links': [{'rel': 'self',
                                   'href': href}]}
            layout.append(resource)
        response = dict(resources=layout)
        content_type = req.best_match_content_type()
        body = wsgi.Serializer(metadata=metadata).serialize(response,
                                                            content_type)
        return webob.Response(body=body, content_type=content_type)


class APIRouter(wsgi.Router):

    @classmethod
    def factory(cls, global_config, **local_config):
        return cls(global_config, **local_config)

    def __init__(self, conf, **local_config):
        mapper = routes_mapper.Mapper()
        plugin_provider = manager.get_plugin_provider(conf)
        plugin = manager.get_plugin(plugin_provider)

        # NOTE(jkoelker) Merge local_conf into conf after the plugin
        #                is discovered
        conf.update(local_config)
        col_kwargs = dict(collection_actions=COLLECTION_ACTIONS,
                          member_actions=MEMBER_ACTIONS)

        resources = {'network': 'networks',
                     'subnet': 'subnets',
                     'port': 'ports'}

        def _map_resource(collection, resource, params):
            controller = base.create_resource(collection, resource,
                                              plugin, conf,
                                              params)
            mapper_kwargs = dict(controller=controller,
                                 requirements=REQUIREMENTS,
                                 **col_kwargs)
            return mapper.collection(collection, resource,
                                     **mapper_kwargs)

        mapper.connect('index', '/', controller=Index(resources))
        for resource in resources:
            _map_resource(resources[resource], resource,
                          RESOURCE_PARAM_MAP.get(resources[resource],
                                                 dict()))

        super(APIRouter, self).__init__(mapper)
