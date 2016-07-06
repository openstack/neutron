# Copyright (c) 2015 OpenStack Foundation.
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

# TODO(asingh): https://review.openstack.org/#/c/338596/ refactors
# neutron.agent.l3.config to neutron.conf.agent.l3.config.
# neutron-fwaas/cmd/eventlet/agents/fw.py imports neutron.agent.l3.config
# This file will be removed when neutron-fwaas imports the updated file
# https://review.openstack.org/#/c/339177/

import neutron.conf.agent.l3.config


OPTS = neutron.conf.agent.l3.config.OPTS
