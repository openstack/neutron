# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Juniper Networks.  All rights reserved.
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
#
# @author: Hampapur Ajay, Praneet Bachheti

import logging
from pprint import pformat
import sys

import cgitb

from contrail_plugin_core import NeutronPluginContrailCoreV2

LOG = logging.getLogger(__name__)


class NeutronPluginContrailPolicy(object):
    def create_policy(self, context, policy):
        """
        Creates a new Policy, and assigns it
        a symbolic name.
        """
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            policy_info = cfgdb.policy_create(policy['policy'])

            # TODO add this in extension
            ##verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            policy_dict = policy_info['q_api_data']
            policy_dict.update(policy_info['q_extra_data'])

            LOG.debug("create_policy(): " + pformat(policy_dict))
            return policy_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_policy(self, context, id, fields=None):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            policy_info = cfgdb.policy_read(id)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            policy_dict = policy_info['q_api_data']
            policy_dict.update(policy_info['q_extra_data'])

            LOG.debug("get_policy(): " + pformat(policy_dict))
            return policy_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def update_policy(self, context, id, policy):
        """
        Updates the attributes of a particular Policy.
        """
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            policy_info = cfgdb.policy_update(id, policy)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            policy_dict = policy_info['q_api_data']
            policy_dict.update(policy_info['q_extra_data'])

            LOG.debug("update_policy(): " + pformat(policy_dict))
            return policy_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def delete_policy(self, context, policy_id):
        """
        Deletes the Policy with the specified identifier
        """
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            cfgdb.policy_delete(policy_id)

            LOG.debug("delete_policy(): " + pformat(policy_id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_policys(self, context, filters=None, fields=None):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            policys_info = cfgdb.policy_list(filters)

            policys_dicts = []
            for policy_info in policys_info:
                # TODO add this in extension
                # verify transformation is conforming to api
                #ipam_dict = self._make_ipam_dict(ipam_info)
                policy_dict = policy_info['q_api_data']
                policy_dict.update(policy_info['q_extra_data'])
                policys_dicts.append(policy_dict)

            LOG.debug("get_policys(): " + pformat(policys_dicts))
            return policys_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_policy_count(self, context, filters=None):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            policy_count = cfgdb.policy_count(filters)
            LOG.debug("get_policy_count(): " + str(policy_count))
            return policy_count
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
