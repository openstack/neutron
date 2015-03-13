# Copyright 2011 Citrix Systems.
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

import oslo_i18n
from oslo_log import log as logging
import webob.dec

from neutron.api.views import versions as versions_view
from neutron import wsgi


LOG = logging.getLogger(__name__)


class Versions(object):

    @classmethod
    def factory(cls, global_config, **local_config):
        return cls()

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        """Respond to a request for all Neutron API versions."""
        version_objs = [
            {
                "id": "v2.0",
                "status": "CURRENT",
            },
        ]

        if req.path != '/':
            language = req.best_match_language()
            msg = _('Unknown API version specified')
            msg = oslo_i18n.translate(msg, language)
            return webob.exc.HTTPNotFound(explanation=msg)

        builder = versions_view.get_view_builder(req)
        versions = [builder.build(version) for version in version_objs]
        response = dict(versions=versions)
        metadata = {}

        content_type = req.best_match_content_type()
        body = (wsgi.Serializer(metadata=metadata).
                serialize(response, content_type))

        response = webob.Response()
        response.content_type = content_type
        response.body = body

        return response
