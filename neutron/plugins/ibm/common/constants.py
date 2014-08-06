# Copyright 2014 IBM Corp.
#
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


import httplib

# Topic for info notifications between the plugin and agent
INFO = 'info'

TENANT_TYPE_OF = 'OF'
TENANT_TYPE_OVERLAY = 'OVERLAY'

HTTP_ACCEPTABLE = [httplib.OK,
                   httplib.CREATED,
                   httplib.ACCEPTED,
                   httplib.NO_CONTENT
                   ]
