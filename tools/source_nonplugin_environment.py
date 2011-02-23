# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Cisco Systems
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
#    @author: Tyler Smith, Cisco Systems
import os
import sys

# To run from the source code, we need to add the various packages
# to our path so we can find all of the modules correctly
packages = ['common', 'server', 'client']

for project in packages + ["plugins/sample-plugin"]:
    sys.path.insert(0, os.path.join(os.getcwd(), project, 'lib'))
