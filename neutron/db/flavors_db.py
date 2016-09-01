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

from neutron_lib.db import model_base
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc as sa_exc

from neutron.api.v2 import attributes as attr
from neutron.db import common_db_mixin
from neutron.db import servicetype_db as sdb
from neutron.extensions import flavors as ext_flavors

LOG = logging.getLogger(__name__)


class Flavor(model_base.BASEV2, model_base.HasId):
    name = sa.Column(sa.String(attr.NAME_MAX_LEN))
    description = sa.Column(sa.String(attr.LONG_DESCRIPTION_MAX_LEN))
    enabled = sa.Column(sa.Boolean, nullable=False, default=True,
                        server_default=sa.sql.true())
    # Make it True for multi-type flavors
    service_type = sa.Column(sa.String(36), nullable=True)
    service_profiles = orm.relationship("FlavorServiceProfileBinding",
        cascade="all, delete-orphan")


class ServiceProfile(model_base.BASEV2, model_base.HasId):
    description = sa.Column(sa.String(attr.LONG_DESCRIPTION_MAX_LEN))
    driver = sa.Column(sa.String(1024), nullable=False)
    enabled = sa.Column(sa.Boolean, nullable=False, default=True,
                        server_default=sa.sql.true())
    metainfo = sa.Column(sa.String(4096))
    flavors = orm.relationship("FlavorServiceProfileBinding")


class FlavorServiceProfileBinding(model_base.BASEV2):
    flavor_id = sa.Column(sa.String(36),
                          sa.ForeignKey("flavors.id",
                                        ondelete="CASCADE"),
                          nullable=False, primary_key=True)
    flavor = orm.relationship(Flavor)
    service_profile_id = sa.Column(sa.String(36),
                                   sa.ForeignKey("serviceprofiles.id",
                                                 ondelete="CASCADE"),
                                   nullable=False, primary_key=True)
    service_profile = orm.relationship(ServiceProfile)


class FlavorsDbMixin(common_db_mixin.CommonDbMixin):

    """Class to support flavors and service profiles."""

    def _get_flavor(self, context, flavor_id):
        try:
            return self._get_by_id(context, Flavor, flavor_id)
        except sa_exc.NoResultFound:
            raise ext_flavors.FlavorNotFound(flavor_id=flavor_id)

    def _get_service_profile(self, context, sp_id):
        try:
            return self._get_by_id(context, ServiceProfile, sp_id)
        except sa_exc.NoResultFound:
            raise ext_flavors.ServiceProfileNotFound(sp_id=sp_id)

    def _make_flavor_dict(self, flavor_db, fields=None):
        res = {'id': flavor_db['id'],
               'name': flavor_db['name'],
               'description': flavor_db['description'],
               'service_type': flavor_db['service_type'],
               'enabled': flavor_db['enabled'],
               'service_profiles': []}
        if flavor_db.service_profiles:
            res['service_profiles'] = [sp['service_profile_id']
                                       for sp in flavor_db.service_profiles]
        return self._fields(res, fields)

    def _make_service_profile_dict(self, sp_db, fields=None):
        res = {'id': sp_db['id'],
               'description': sp_db['description'],
               'driver': sp_db['driver'],
               'enabled': sp_db['enabled'],
               'metainfo': sp_db['metainfo']}
        if sp_db.flavors:
            res['flavors'] = [fl['flavor_id']
                              for fl in sp_db.flavors]
        return self._fields(res, fields)

    def _ensure_flavor_not_in_use(self, context, flavor_id):
        """Checks that flavor is not associated with service instance."""
        # Future TODO(enikanorov): check that there is no binding to
        # instances. Shall address in future upon getting the right
        # flavor supported driver
        pass

    def _ensure_service_profile_not_in_use(self, context, sp_id):
        """Ensures no current bindings to flavors exist."""
        fl = (context.session.query(FlavorServiceProfileBinding).
              filter_by(service_profile_id=sp_id).first())
        if fl:
            raise ext_flavors.ServiceProfileInUse(sp_id=sp_id)

    def _validate_driver(self, context, driver):
        """Confirms a non-empty driver is a valid provider."""
        service_type_manager = sdb.ServiceTypeManager.get_instance()
        providers = service_type_manager.get_service_providers(
            context,
            filters={'driver': driver})

        if not providers:
            raise ext_flavors.ServiceProfileDriverNotFound(driver=driver)

    def create_flavor(self, context, flavor):
        fl = flavor['flavor']
        with context.session.begin(subtransactions=True):
            fl_db = Flavor(id=uuidutils.generate_uuid(),
                           name=fl['name'],
                           description=fl['description'],
                           service_type=fl['service_type'],
                           enabled=fl['enabled'])
            context.session.add(fl_db)
        return self._make_flavor_dict(fl_db)

    def update_flavor(self, context, flavor_id, flavor):
        fl = flavor['flavor']
        with context.session.begin(subtransactions=True):
            self._ensure_flavor_not_in_use(context, flavor_id)
            fl_db = self._get_flavor(context, flavor_id)
            fl_db.update(fl)
        return self._make_flavor_dict(fl_db)

    def get_flavor(self, context, flavor_id, fields=None):
        fl = self._get_flavor(context, flavor_id)
        return self._make_flavor_dict(fl, fields)

    def delete_flavor(self, context, flavor_id):
        with context.session.begin(subtransactions=True):
            self._ensure_flavor_not_in_use(context, flavor_id)
            fl_db = self._get_flavor(context, flavor_id)
            context.session.delete(fl_db)

    def get_flavors(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None, page_reverse=False):
        return self._get_collection(context, Flavor, self._make_flavor_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker,
                                    page_reverse=page_reverse)

    def create_flavor_service_profile(self, context,
                                      service_profile, flavor_id):
        sp = service_profile['service_profile']
        with context.session.begin(subtransactions=True):
            bind_qry = context.session.query(FlavorServiceProfileBinding)
            binding = bind_qry.filter_by(service_profile_id=sp['id'],
                                         flavor_id=flavor_id).first()
            if binding:
                raise ext_flavors.FlavorServiceProfileBindingExists(
                    sp_id=sp['id'], fl_id=flavor_id)
            binding = FlavorServiceProfileBinding(
                service_profile_id=sp['id'],
                flavor_id=flavor_id)
            context.session.add(binding)
        fl_db = self._get_flavor(context, flavor_id)
        return self._make_flavor_dict(fl_db)

    def delete_flavor_service_profile(self, context,
                                      service_profile_id, flavor_id):
        with context.session.begin(subtransactions=True):
            binding = (context.session.query(FlavorServiceProfileBinding).
                       filter_by(service_profile_id=service_profile_id,
                       flavor_id=flavor_id).first())
            if not binding:
                raise ext_flavors.FlavorServiceProfileBindingNotFound(
                    sp_id=service_profile_id, fl_id=flavor_id)
            context.session.delete(binding)

    def get_flavor_service_profile(self, context,
                                   service_profile_id, flavor_id, fields=None):
        with context.session.begin(subtransactions=True):
            binding = (context.session.query(FlavorServiceProfileBinding).
                       filter_by(service_profile_id=service_profile_id,
                       flavor_id=flavor_id).first())
            if not binding:
                raise ext_flavors.FlavorServiceProfileBindingNotFound(
                    sp_id=service_profile_id, fl_id=flavor_id)
        res = {'service_profile_id': service_profile_id,
               'flavor_id': flavor_id}
        return self._fields(res, fields)

    def create_service_profile(self, context, service_profile):
        sp = service_profile['service_profile']

        if sp['driver']:
            self._validate_driver(context, sp['driver'])
        else:
            if not sp['metainfo']:
                raise ext_flavors.ServiceProfileEmpty()

        with context.session.begin(subtransactions=True):
            sp_db = ServiceProfile(id=uuidutils.generate_uuid(),
                                   description=sp['description'],
                                   driver=sp['driver'],
                                   enabled=sp['enabled'],
                                   metainfo=sp['metainfo'])
            context.session.add(sp_db)

        return self._make_service_profile_dict(sp_db)

    def update_service_profile(self, context,
                               service_profile_id, service_profile):
        sp = service_profile['service_profile']

        if sp.get('driver'):
            self._validate_driver(context, sp['driver'])

        with context.session.begin(subtransactions=True):
            self._ensure_service_profile_not_in_use(context,
                                                    service_profile_id)
            sp_db = self._get_service_profile(context, service_profile_id)
            sp_db.update(sp)
        return self._make_service_profile_dict(sp_db)

    def get_service_profile(self, context, sp_id, fields=None):
        sp_db = self._get_service_profile(context, sp_id)
        return self._make_service_profile_dict(sp_db, fields)

    def delete_service_profile(self, context, sp_id):
        with context.session.begin(subtransactions=True):
            self._ensure_service_profile_not_in_use(context, sp_id)
            sp_db = self._get_service_profile(context, sp_id)
            context.session.delete(sp_db)

    def get_service_profiles(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        return self._get_collection(context, ServiceProfile,
                                    self._make_service_profile_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker,
                                    page_reverse=page_reverse)

    def get_flavor_next_provider(self, context, flavor_id,
                                 filters=None, fields=None,
                                 sorts=None, limit=None,
                                 marker=None, page_reverse=False):
        """From flavor, choose service profile and find provider for driver."""

        with context.session.begin(subtransactions=True):
            bind_qry = context.session.query(FlavorServiceProfileBinding)
            binding = bind_qry.filter_by(flavor_id=flavor_id).first()
            if not binding:
                raise ext_flavors.FlavorServiceProfileBindingNotFound(
                    sp_id='', fl_id=flavor_id)

        # Get the service profile from the first binding
        # TODO(jwarendt) Should become a scheduling framework instead
        sp_db = self._get_service_profile(context,
                                          binding['service_profile_id'])

        if not sp_db.enabled:
            raise ext_flavors.ServiceProfileDisabled()

        LOG.debug("Found driver %s.", sp_db.driver)

        service_type_manager = sdb.ServiceTypeManager.get_instance()
        providers = service_type_manager.get_service_providers(
            context,
            filters={'driver': sp_db.driver})

        if not providers:
            raise ext_flavors.ServiceProfileDriverNotFound(driver=sp_db.driver)

        LOG.debug("Found providers %s.", providers)

        res = {'driver': sp_db.driver,
               'provider': providers[0].get('name')}

        return [self._fields(res, fields)]
