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

from neutron_lib.db import api as db_api
from neutron_lib.db import utils as db_utils
from neutron_lib.exceptions import flavors as flav_exc
from oslo_db import exception as db_exc
from oslo_log import log as logging

from neutron.db import servicetype_db as sdb
from neutron.objects import base as base_obj
from neutron.objects import flavor as obj_flavor


LOG = logging.getLogger(__name__)


class FlavorsDbMixin:

    """Class to support flavors and service profiles."""

    def _get_flavor(self, context, flavor_id):
        flavor = obj_flavor.Flavor.get_object(context, id=flavor_id)
        if not flavor:
            raise flav_exc.FlavorNotFound(flavor_id=flavor_id)
        return flavor

    def _get_service_profile(self, context, sp_id):
        service_profile = obj_flavor.ServiceProfile.get_object(
            context, id=sp_id)
        if not service_profile:
            raise flav_exc.ServiceProfileNotFound(sp_id=sp_id)
        return service_profile

    @staticmethod
    def _make_flavor_dict(flavor_obj, fields=None):
        res = {'id': flavor_obj['id'],
               'name': flavor_obj['name'],
               'description': flavor_obj['description'],
               'service_type': flavor_obj['service_type'],
               'enabled': flavor_obj['enabled'],
               'service_profiles': list(flavor_obj['service_profile_ids'])}

        return db_utils.resource_fields(res, fields)

    @staticmethod
    def _make_service_profile_dict(sp_obj, fields=None):
        res = {'id': sp_obj['id'],
               'description': sp_obj['description'],
               'driver': sp_obj['driver'],
               'enabled': sp_obj['enabled'],
               'metainfo': sp_obj['metainfo'],
               'flavors': list(sp_obj['flavor_ids'])}
        return db_utils.resource_fields(res, fields)

    def _ensure_flavor_not_in_use(self, context, flavor_id):
        """Checks that flavor is not associated with service instance."""
        # Future TODO(enikanorov): check that there is no binding to
        # instances. Shall address in future upon getting the right
        # flavor supported driver
        # NOTE(kevinbenton): sqlalchemy utils has a cool dependent
        # objects function we can use to quickly query all tables
        # that have a foreign key ref to flavors. Or we could replace
        # the call to this with callback events.
        pass

    def _ensure_service_profile_not_in_use(self, context, sp_id):
        """Ensures no current bindings to flavors exist."""
        if obj_flavor.FlavorServiceProfileBinding.objects_exist(
                context, service_profile_id=sp_id):
            raise flav_exc.ServiceProfileInUse(sp_id=sp_id)

    def _validate_driver(self, context, driver):
        """Confirms a non-empty driver is a valid provider."""
        service_type_manager = sdb.ServiceTypeManager.get_instance()
        providers = service_type_manager.get_service_providers(
            context,
            filters={'driver': driver})

        if not providers:
            raise flav_exc.ServiceProfileDriverNotFound(driver=driver)

    def create_flavor(self, context, flavor):
        fl = flavor['flavor']
        obj = obj_flavor.Flavor(
            context, name=fl['name'], description=fl['description'],
            service_type=fl['service_type'], enabled=fl['enabled'])
        obj.create()
        return self._make_flavor_dict(obj)

    def update_flavor(self, context, flavor_id, flavor):
        with db_api.CONTEXT_WRITER.using(context):
            self._ensure_flavor_not_in_use(context, flavor_id)
            fl_obj = self._get_flavor(context, flavor_id)
            fl_obj.update_fields(flavor['flavor'])
            fl_obj.update()
        return self._make_flavor_dict(fl_obj)

    def get_flavor(self, context, flavor_id, fields=None):
        fl = self._get_flavor(context, flavor_id)
        return self._make_flavor_dict(fl, fields)

    def delete_flavor(self, context, flavor_id):
        # NOTE(kevinbenton): we need to fix _ensure_flavor_not_in_use,
        # but the fix is non-trivial since multiple services can use
        # flavors so for now we just capture the foreign key violation
        # to detect if it's in use.
        try:
            with db_api.CONTEXT_WRITER.using(context):
                self._ensure_flavor_not_in_use(context, flavor_id)
                self._get_flavor(context, flavor_id).delete()
        except db_exc.DBReferenceError:
            raise flav_exc.FlavorInUse(flavor_id=flavor_id)

    def get_flavors(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None, page_reverse=False):
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        filters = filters or {}
        flavor_objs = obj_flavor.Flavor.get_objects(context, _pager=pager,
                                                    **filters)
        return [self._make_flavor_dict(flavor_object, fields)
                for flavor_object in flavor_objs]

    def create_flavor_service_profile(self, context,
                                      service_profile, flavor_id):
        sp = service_profile['service_profile']
        with db_api.CONTEXT_WRITER.using(context):
            if obj_flavor.FlavorServiceProfileBinding.objects_exist(
                    context, service_profile_id=sp['id'], flavor_id=flavor_id):
                raise flav_exc.FlavorServiceProfileBindingExists(
                    sp_id=sp['id'], fl_id=flavor_id)
            obj_flavor.FlavorServiceProfileBinding(
                context, service_profile_id=sp['id'],
                flavor_id=flavor_id).create()
        fl_obj = self._get_flavor(context, flavor_id)
        return self._make_flavor_dict(fl_obj)

    def delete_flavor_service_profile(self, context,
                                      service_profile_id, flavor_id):
        if (obj_flavor.FlavorServiceProfileBinding.delete_objects(
                context, service_profile_id=service_profile_id,
                flavor_id=flavor_id) == 0):
            raise flav_exc.FlavorServiceProfileBindingNotFound(
                sp_id=service_profile_id, fl_id=flavor_id)

    @staticmethod
    def get_flavor_service_profile(context,
                                   service_profile_id, flavor_id, fields=None):
        if not obj_flavor.FlavorServiceProfileBinding.objects_exist(
                context, service_profile_id=service_profile_id,
                flavor_id=flavor_id):
            raise flav_exc.FlavorServiceProfileBindingNotFound(
                sp_id=service_profile_id, fl_id=flavor_id)
        res = {'service_profile_id': service_profile_id,
               'flavor_id': flavor_id}
        return db_utils.resource_fields(res, fields)

    def create_service_profile(self, context, service_profile):
        sp = service_profile['service_profile']

        if sp['driver']:
            self._validate_driver(context, sp['driver'])
        else:
            if not sp['metainfo']:
                raise flav_exc.ServiceProfileEmpty()

        obj = obj_flavor.ServiceProfile(
            context, description=sp['description'], driver=sp['driver'],
            enabled=sp['enabled'], metainfo=sp['metainfo'])
        obj.create()
        return self._make_service_profile_dict(obj)

    def update_service_profile(self, context,
                               service_profile_id, service_profile):
        sp = service_profile['service_profile']

        if sp.get('driver'):
            self._validate_driver(context, sp['driver'])

        with db_api.CONTEXT_WRITER.using(context):
            self._ensure_service_profile_not_in_use(context,
                                                    service_profile_id)
            sp_obj = self._get_service_profile(context, service_profile_id)
            sp_obj.update_fields(sp)
            sp_obj.update()
            return self._make_service_profile_dict(sp_obj)

    def get_service_profile(self, context, sp_id, fields=None):
        sp_db = self._get_service_profile(context, sp_id)
        return self._make_service_profile_dict(sp_db, fields)

    def delete_service_profile(self, context, sp_id):
        with db_api.CONTEXT_WRITER.using(context):
            self._ensure_service_profile_not_in_use(context, sp_id)
            self._get_service_profile(context, sp_id).delete()

    def get_service_profiles(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        filters = filters or {}
        sp_objs = obj_flavor.ServiceProfile.get_objects(context, _pager=pager,
                                                        **filters)
        return [self._make_service_profile_dict(sp_obj, fields)
                for sp_obj in sp_objs]

    def get_flavor_next_provider(self, context, flavor_id,
                                 filters=None, fields=None,
                                 sorts=None, limit=None,
                                 marker=None, page_reverse=False):
        """From flavor, choose service profile and find provider for driver."""

        objs = obj_flavor.FlavorServiceProfileBinding.get_objects(
            context, flavor_id=flavor_id)
        if not objs:
            raise flav_exc.FlavorServiceProfileBindingNotFound(
                sp_id='', fl_id=flavor_id)
        # Get the service profile from the first binding
        # TODO(jwarendt) Should become a scheduling framework instead
        sp_obj = self._get_service_profile(context, objs[0].service_profile_id)

        if not sp_obj.enabled:
            raise flav_exc.ServiceProfileDisabled()

        LOG.debug("Found driver %s.", sp_obj.driver)

        service_type_manager = sdb.ServiceTypeManager.get_instance()
        providers = service_type_manager.get_service_providers(
            context,
            filters={'driver': sp_obj.driver})

        if not providers:
            raise flav_exc.ServiceProfileDriverNotFound(
                driver=sp_obj.driver)

        LOG.debug("Found providers %s.", providers)

        res = {'driver': sp_obj.driver,
               'provider': providers[0].get('name')}

        return [db_utils.resource_fields(res, fields)]
