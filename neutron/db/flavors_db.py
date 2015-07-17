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

from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc as sa_exc

from neutron.common import exceptions as qexception
from neutron.db import common_db_mixin
from neutron.db import model_base
from neutron.db import models_v2
from neutron.plugins.common import constants


LOG = logging.getLogger(__name__)


# Flavor Exceptions
class FlavorNotFound(qexception.NotFound):
    message = _("Flavor %(flavor_id)s could not be found")


class FlavorInUse(qexception.InUse):
    message = _("Flavor %(flavor_id)s is used by some service instance")


class ServiceProfileNotFound(qexception.NotFound):
    message = _("Service Profile %(sp_id)s could not be found")


class ServiceProfileInUse(qexception.InUse):
    message = _("Service Profile %(sp_id)s is used by some service instance")


class FlavorServiceProfileBindingExists(qexception.Conflict):
    message = _("Service Profile %(sp_id)s is already associated "
                "with flavor %(fl_id)s")


class FlavorServiceProfileBindingNotFound(qexception.NotFound):
    message = _("Service Profile %(sp_id)s is not associated "
                "with flavor %(fl_id)s")


class DummyCorePlugin(object):
    pass


class DummyServicePlugin(object):

    def driver_loaded(self, driver, service_profile):
        pass

    def get_plugin_type(self):
        return constants.DUMMY

    def get_plugin_description(self):
        return "Dummy service plugin, aware of flavors"


class DummyServiceDriver(object):

    @staticmethod
    def get_service_type():
        return constants.DUMMY

    def __init__(self, plugin):
        pass


class Flavor(model_base.BASEV2, models_v2.HasId):
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    enabled = sa.Column(sa.Boolean, nullable=False, default=True,
                        server_default=sa.sql.true())
    # Make it True for multi-type flavors
    service_type = sa.Column(sa.String(36), nullable=True)
    service_profiles = orm.relationship("FlavorServiceProfileBinding",
        cascade="all, delete-orphan")


class ServiceProfile(model_base.BASEV2, models_v2.HasId):
    description = sa.Column(sa.String(1024))
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


class FlavorManager(common_db_mixin.CommonDbMixin):
    """Class to support flavors and service profiles."""

    supported_extension_aliases = ["flavors"]

    def __init__(self, manager=None):
        # manager = None is UT usage where FlavorManager is loaded as
        # a core plugin
        self.manager = manager

    def get_plugin_name(self):
        return constants.FLAVORS

    def get_plugin_type(self):
        return constants.FLAVORS

    def get_plugin_description(self):
        return "Neutron Flavors and Service Profiles manager plugin"

    def _get_flavor(self, context, flavor_id):
        try:
            return self._get_by_id(context, Flavor, flavor_id)
        except sa_exc.NoResultFound:
            raise FlavorNotFound(flavor_id=flavor_id)

    def _get_service_profile(self, context, sp_id):
        try:
            return self._get_by_id(context, ServiceProfile, sp_id)
        except sa_exc.NoResultFound:
            raise ServiceProfileNotFound(sp_id=sp_id)

    def _make_flavor_dict(self, flavor_db, fields=None):
        res = {'id': flavor_db['id'],
               'name': flavor_db['name'],
               'description': flavor_db['description'],
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
        # Future TODO(enikanorov): check that there is no binding to instances
        # and no binding to flavors. Shall be addressed in future
        fl = (context.session.query(FlavorServiceProfileBinding).
              filter_by(service_profile_id=sp_id).first())
        if fl:
            raise ServiceProfileInUse(sp_id=sp_id)

    def create_flavor(self, context, flavor):
        fl = flavor['flavor']
        with context.session.begin(subtransactions=True):
            fl_db = Flavor(id=uuidutils.generate_uuid(),
                           name=fl['name'],
                           description=fl['description'],
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
                raise FlavorServiceProfileBindingExists(
                    sp_id=sp['id'], fl_id=flavor_id)
            binding = FlavorServiceProfileBinding(
                service_profile_id=sp['id'],
                flavor_id=flavor_id)
            context.session.add(binding)
        fl_db = self._get_flavor(context, flavor_id)
        sps = [x['service_profile_id'] for x in fl_db.service_profiles]
        return sps

    def delete_flavor_service_profile(self, context,
                                      service_profile_id, flavor_id):
        with context.session.begin(subtransactions=True):
            binding = (context.session.query(FlavorServiceProfileBinding).
                       filter_by(service_profile_id=service_profile_id,
                       flavor_id=flavor_id).first())
            if not binding:
                raise FlavorServiceProfileBindingNotFound(
                    sp_id=service_profile_id, fl_id=flavor_id)
            context.session.delete(binding)

    def get_flavor_service_profile(self, context,
                                   service_profile_id, flavor_id, fields=None):
        with context.session.begin(subtransactions=True):
            binding = (context.session.query(FlavorServiceProfileBinding).
                       filter_by(service_profile_id=service_profile_id,
                       flavor_id=flavor_id).first())
            if not binding:
                raise FlavorServiceProfileBindingNotFound(
                    sp_id=service_profile_id, fl_id=flavor_id)
        res = {'service_profile_id': service_profile_id,
               'flavor_id': flavor_id}
        return self._fields(res, fields)

    def _load_dummy_driver(self, driver):
        driver = DummyServiceDriver
        driver_klass = driver
        return driver_klass

    def _load_driver(self, profile):
        driver_klass = importutils.import_class(profile.driver)
        return driver_klass

    def create_service_profile(self, context, service_profile):
        sp = service_profile['service_profile']
        with context.session.begin(subtransactions=True):
            driver_klass = self._load_dummy_driver(sp['driver'])
            # 'get_service_type' must be a static method so it cant be changed
            svc_type = DummyServiceDriver.get_service_type()

            sp_db = ServiceProfile(id=uuidutils.generate_uuid(),
                                   description=sp['description'],
                                   driver=svc_type,
                                   enabled=sp['enabled'],
                                   metainfo=jsonutils.dumps(sp['metainfo']))
            context.session.add(sp_db)
        try:
            # driver_klass = self._load_dummy_driver(sp_db)
            # Future TODO(madhu_ak): commented for now to load dummy driver
            # until there is flavor supported driver
            # plugin = self.manager.get_service_plugins()[svc_type]
            # plugin.driver_loaded(driver_klass(plugin), sp_db)
            # svc_type = DummyServiceDriver.get_service_type()
            # plugin = self.manager.get_service_plugins()[svc_type]
            # plugin = FlavorManager(manager.NeutronManager().get_instance())
            # plugin = DummyServicePlugin.get_plugin_type(svc_type)
            plugin = DummyServicePlugin()
            plugin.driver_loaded(driver_klass(svc_type), sp_db)
        except Exception:
            # Future TODO(enikanorov): raise proper exception
            self.delete_service_profile(context, sp_db['id'])
            raise
        return self._make_service_profile_dict(sp_db)

    def unit_create_service_profile(self, context, service_profile):
        # Note: Triggered by unit tests pointing to dummy driver
        sp = service_profile['service_profile']
        with context.session.begin(subtransactions=True):
            sp_db = ServiceProfile(id=uuidutils.generate_uuid(),
                                   description=sp['description'],
                                   driver=sp['driver'],
                                   enabled=sp['enabled'],
                                   metainfo=sp['metainfo'])
            context.session.add(sp_db)
        try:
            driver_klass = self._load_driver(sp_db)
            # require get_service_type be a static method
            svc_type = driver_klass.get_service_type()
            plugin = self.manager.get_service_plugins()[svc_type]
            plugin.driver_loaded(driver_klass(plugin), sp_db)
        except Exception:
            # Future TODO(enikanorov): raise proper exception
            self.delete_service_profile(context, sp_db['id'])
            raise
        return self._make_service_profile_dict(sp_db)

    def update_service_profile(self, context,
                               service_profile_id, service_profile):
        sp = service_profile['service_profile']
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
