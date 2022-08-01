# Copyright (c) 2022 Red Hat, Inc.
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

from neutron_lib.db import quota_api as nlib_quota_api


class DbQuotaDriverNull(nlib_quota_api.QuotaDriverAPI):

    @staticmethod
    def get_default_quotas(context, resources, project_id):
        return {}

    @staticmethod
    def get_project_quotas(context, resources, project_id):
        return {}

    @staticmethod
    def get_detailed_project_quotas(context, resources, project_id):
        return {}

    @staticmethod
    def delete_project_quota(context, project_id):
        pass

    @staticmethod
    def get_all_quotas(context, resources):
        return []

    @staticmethod
    def update_quota_limit(context, project_id, resource, limit):
        pass

    @staticmethod
    def make_reservation(context, project_id, resources, deltas, plugin):
        pass

    @staticmethod
    def commit_reservation(context, reservation_id):
        pass

    @staticmethod
    def cancel_reservation(context, reservation_id):
        pass

    @staticmethod
    def limit_check(context, project_id, resources, values):
        pass

    @staticmethod
    def get_resource_usage(context, project_id, resources, resource_name):
        return 0

    @staticmethod
    def get_resource_count(context, project_id, tracked_resource):
        return 0

    @staticmethod
    def quota_limit_check(context, project_id, resources, deltas):
        pass

    @staticmethod
    def get_workers():
        return []
