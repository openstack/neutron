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


class NeutronPluginContrailIpam(object):

    def create_ipam(self, context, ipam):
        """
        Creates a new IPAM, and assigns it
        a symbolic name.
        """
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            ipam_info = cfgdb.ipam_create(ipam['ipam'])

            # TODO add this in extension
            ##verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])

            LOG.debug("create_ipam(): " + pformat(ipam_dict))
            return ipam_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_ipam(self, context, id, fields=None):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            ipam_info = cfgdb.ipam_read(id)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])

            LOG.debug("get_ipam(): " + pformat(ipam_dict))
            return ipam_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def update_ipam(self, context, id, ipam):
        """
        Updates the attributes of a particular IPAM.
        """
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            ipam_info = cfgdb.ipam_update(id, ipam)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])

            LOG.debug("update_ipam(): " + pformat(ipam_dict))
            return ipam_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def delete_ipam(self, context, ipam_id):
        """
        Deletes the ipam with the specified identifier
        """
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            cfgdb.ipam_delete(ipam_id)

            LOG.debug("delete_ipam(): " + pformat(ipam_id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_ipams(self, context, filters=None, fields=None):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            ipams_info = cfgdb.ipam_list(filters)

            ipams_dicts = []
            for ipam_info in ipams_info:
                # TODO add this in extension
                # verify transformation is conforming to api
                #ipam_dict = self._make_ipam_dict(ipam_info)
                ipam_dict = ipam_info['q_api_data']
                ipam_dict.update(ipam_info['q_extra_data'])
                ipams_dicts.append(ipam_dict)

            LOG.debug("get_ipams(): " + pformat(ipams_dicts))
            return ipams_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_ipams_count(self, context, filters=None):
        try:
            cfgdb = NeutronPluginContrailCoreV2._get_user_cfgdb(context)
            ipams_count = cfgdb.ipams_count(filters)
            LOG.debug("get_ipams_count(): " + str(ipams_count))
            return ipams_count
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
