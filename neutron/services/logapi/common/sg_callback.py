# Copyright (c) 2018 Fujitsu Limited
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

from neutron.services.logapi.common import constants as log_const
from neutron.services.logapi.common import db_api
from neutron.services.logapi.drivers import manager


class SecurityGroupRuleCallBack(manager.ResourceCallBackBase):

    def handle_event(self, resource, event, trigger, **kwargs):
        context = kwargs.get("context")
        sg_rule = kwargs.get('security_group_rule')
        if sg_rule:
            sg_id = sg_rule.get('security_group_id')
        else:
            sg_id = kwargs.get('security_group_id')

        log_resources = db_api.get_logs_bound_sg(context, sg_id)
        if log_resources:
            self.resource_push_api(
                log_const.RESOURCE_UPDATE, context, log_resources)
