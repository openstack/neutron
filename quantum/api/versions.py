# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import logging
import webob.dec

from quantum import wsgi
from quantum.api.views import versions as versions_view


LOG = logging.getLogger(__name__)


class Versions(object):

    @classmethod
    def factory(cls, global_config, **local_config):
        return cls()

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        """Respond to a request for all Quantum API versions."""
        version_objs = [
            {
                "id": "v1.0",
                "status": "DEPRECATED",
            },
            {
                "id": "v1.1",
                "status": "CURRENT",
            },
            {
                "id": "v2.0",
                "status": "PROPOSED",
            },
        ]

        if req.path != '/':
            return webob.exc.HTTPNotFound()

        builder = versions_view.get_view_builder(req)
        versions = [builder.build(version) for version in version_objs]
        response = dict(versions=versions)
        metadata = {
            "application/xml": {
                "attributes": {
                    "version": ["status", "id"],
                    "link": ["rel", "href"],
                }
            }
        }

        content_type = req.best_match_content_type()
        body = wsgi.Serializer(metadata=metadata). \
                    serialize(response, content_type)

        response = webob.Response()
        response.content_type = content_type
        response.body = body

        return response
