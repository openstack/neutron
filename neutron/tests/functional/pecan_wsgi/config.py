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

# use main app settings except for the port number so testing doesn't need to
# listen on the main neutron port
app = {
    'root': 'neutron.pecan_wsgi.controllers.root.RootController',
    'modules': ['neutron.pecan_wsgi'],
    'errors': {
        400: '/error',
        '__force_dict__': True
    }
}
