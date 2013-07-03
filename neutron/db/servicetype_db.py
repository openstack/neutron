# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 OpenStack Foundation.
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
#
#    @author: Salvatore Orlando, VMware
#

from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc as orm_exc
from sqlalchemy.sql import expression as expr

from neutron.common import exceptions as q_exc
from neutron import context
from neutron.db import api as db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)
DEFAULT_SVCTYPE_NAME = 'default'

default_servicetype_opts = [
    cfg.StrOpt('description',
               default='',
               help=_('Textual description for the default service type')),
    cfg.MultiStrOpt('service_definition',
                    help=_('Defines a provider for an advanced service '
                           'using the format: <service>:<plugin>[:<driver>]'))
]

cfg.CONF.register_opts(default_servicetype_opts, 'default_servicetype')


def parse_service_definition_opt():
    """Parse service definition opts and returns result."""
    results = []
    svc_def_opt = cfg.CONF.default_servicetype.service_definition
    try:
        for svc_def_str in svc_def_opt:
            split = svc_def_str.split(':')
            svc_def = {'service_class': split[0],
                       'plugin': split[1]}
            try:
                svc_def['driver'] = split[2]
            except IndexError:
                # Never mind, driver is optional
                LOG.debug(_("Default service type - no driver for service "
                            "%(service_class)s and plugin %(plugin)s"),
                          svc_def)
            results.append(svc_def)
        return results
    except (TypeError, IndexError):
        raise q_exc.InvalidConfigurationOption(opt_name='service_definition',
                                               opt_value=svc_def_opt)


class NoDefaultServiceDefinition(q_exc.NeutronException):
    message = _("No default service definition in configuration file. "
                "Please add service definitions using the service_definition "
                "variable in the [default_servicetype] section")


class ServiceTypeNotFound(q_exc.NotFound):
    message = _("Service type %(service_type_id)s could not be found ")


class ServiceTypeInUse(q_exc.InUse):
    message = _("There are still active instances of service type "
                "'%(service_type_id)s'. Therefore it cannot be removed.")


class ServiceDefinition(model_base.BASEV2, models_v2.HasId):
    service_class = sa.Column(sa.String(255), primary_key=True)
    plugin = sa.Column(sa.String(255))
    driver = sa.Column(sa.String(255))
    service_type_id = sa.Column(sa.String(36),
                                sa.ForeignKey('servicetypes.id',
                                              ondelete='CASCADE'),
                                primary_key=True)


class ServiceType(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Service Type Object Model."""
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    default = sa.Column(sa.Boolean(), nullable=False, default=False)
    service_definitions = orm.relationship(ServiceDefinition,
                                           backref='servicetypes',
                                           lazy='joined',
                                           cascade='all')
    # Keep track of number of instances for this service type
    num_instances = sa.Column(sa.Integer(), default=0)

    def as_dict(self):
        """Convert a row into a dict."""
        ret_dict = {}
        for c in self.__table__.columns:
            ret_dict[c.name] = getattr(self, c.name)
        return ret_dict


class ServiceTypeManager(object):
    """Manage service type objects in Neutron database."""

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._initialize_db()
        ctx = context.get_admin_context()
        # Init default service type from configuration file
        svc_defs = cfg.CONF.default_servicetype.service_definition
        if not svc_defs:
            raise NoDefaultServiceDefinition()
        def_service_type = {'name': DEFAULT_SVCTYPE_NAME,
                            'description':
                            cfg.CONF.default_servicetype.description,
                            'service_definitions':
                            parse_service_definition_opt(),
                            'default': True}
        # Create or update record in database
        def_svc_type_db = self._get_default_service_type(ctx)
        if not def_svc_type_db:
            def_svc_type_db = self._create_service_type(ctx, def_service_type)
        else:
            self._update_service_type(ctx,
                                      def_svc_type_db['id'],
                                      def_service_type,
                                      svc_type_db=def_svc_type_db)
        LOG.debug(_("Default service type record updated in Neutron database. "
                    "identifier is '%s'"), def_svc_type_db['id'])

    def _initialize_db(self):
        db.configure_db()
        # Register models for service type management
        # Note this might have been already done if configure_db also
        # created the engine
        db.register_models(models_v2.model_base.BASEV2)

    def _create_service_type(self, context, service_type):
        svc_defs = service_type.pop('service_definitions')
        with context.session.begin(subtransactions=True):
            svc_type_db = ServiceType(**service_type)
            # and now insert provided service type definitions
            for svc_def in svc_defs:
                svc_type_db.service_definitions.append(
                    ServiceDefinition(**svc_def))
            # sqlalchemy save-update on relationship is on by
            # default, the following will save both the service
            # type and its service definitions
            context.session.add(svc_type_db)
        return svc_type_db

    def _update_service_type(self, context, id, service_type,
                             svc_type_db=None):
        with context.session.begin(subtransactions=True):
            if not svc_type_db:
                svc_type_db = self._get_service_type(context, id)
            try:
                svc_defs_map = dict([(svc_def['service'], svc_def)
                                     for svc_def in
                                     service_type.pop('service_definitions')])
            except KeyError:
                # No service defs in request
                svc_defs_map = {}
            svc_type_db.update(service_type)
            for svc_def_db in svc_type_db.service_definitions:
                try:
                    svc_def_db.update(svc_defs_map.pop(
                        svc_def_db['service_class']))
                except KeyError:
                    # too bad, the service def was not there
                    # then we should delete it.
                    context.session.delete(svc_def_db)
            # Add remaining service definitions
            for svc_def in svc_defs_map:
                context.session.add(ServiceDefinition(**svc_def))
        return svc_type_db

    def _get_service_type(self, context, svc_type_id):
        try:
            query = context.session.query(ServiceType)
            return query.filter(ServiceType.id == svc_type_id).one()
            # filter is on primary key, do not catch MultipleResultsFound
        except orm_exc.NoResultFound:
            raise ServiceTypeNotFound(service_type_id=svc_type_id)

    def _get_default_service_type(self, context):
        try:
            query = context.session.query(ServiceType)
            return query.filter(ServiceType.default == expr.true()).one()
        except orm_exc.NoResultFound:
            return
        except orm_exc.MultipleResultsFound:
            # This should never happen. If it does, take the first instance
            query2 = context.session.query(ServiceType)
            results = query2.filter(ServiceType.default == expr.true()).all()
            LOG.warning(_("Multiple default service type instances found."
                          "Will use instance '%s'"), results[0]['id'])
            return results[0]

    def _make_svc_type_dict(self, context, svc_type, fields=None):

        def _make_svc_def_dict(svc_def_db):
            svc_def = {'service_class': svc_def_db['service_class']}
            svc_def.update({'plugin': svc_def_db['plugin'],
                            'driver': svc_def_db['driver']})
            return svc_def

        res = {'id': svc_type['id'],
               'name': svc_type['name'],
               'default': svc_type['default'],
               'num_instances': svc_type['num_instances'],
               'service_definitions':
               [_make_svc_def_dict(svc_def) for svc_def
                in svc_type['service_definitions']]}
        # Field selection
        if fields:
            return dict(((k, v) for k, v in res.iteritems()
                         if k in fields))
        return res

    def get_service_type(self, context, id, fields=None):
        """Retrieve a service type record."""
        return self._make_svc_type_dict(context,
                                        self._get_service_type(context, id),
                                        fields)

    def get_service_types(self, context, fields=None, filters=None):
        """Retrieve a possibly filtered list of service types."""
        query = context.session.query(ServiceType)
        if filters:
            for key, value in filters.iteritems():
                column = getattr(ServiceType, key, None)
                if column:
                    query = query.filter(column.in_(value))
        return [self._make_svc_type_dict(context, svc_type, fields)
                for svc_type in query]

    def create_service_type(self, context, service_type):
        """Create a new service type."""
        svc_type_data = service_type['service_type']
        svc_type_db = self._create_service_type(context, svc_type_data)
        LOG.debug(_("Created service type object:%s"), svc_type_db['id'])
        return self._make_svc_type_dict(context, svc_type_db)

    def update_service_type(self, context, id, service_type):
        """Update a service type."""
        svc_type_data = service_type['service_type']
        svc_type_db = self._update_service_type(context, id,
                                                svc_type_data)
        return self._make_svc_type_dict(context, svc_type_db)

    def delete_service_type(self, context, id):
        """Delete a service type."""
        # Verify that the service type is not in use.
        svc_type_db = self._get_service_type(context, id)
        if svc_type_db['num_instances'] > 0:
            raise ServiceTypeInUse(service_type_id=svc_type_db['id'])
        with context.session.begin(subtransactions=True):
            context.session.delete(svc_type_db)

    def increase_service_type_refcount(self, context, id):
        """Increase references count for a service type object

        This method should be invoked by plugins using the service
        type concept everytime an instance of an object associated
        with a given service type is created.
        """
        #TODO(salvatore-orlando): Devise a better solution than this
        #refcount mechanisms. Perhaps adding hooks into models which
        #use service types in order to enforce ref. integrity and cascade
        with context.session.begin(subtransactions=True):
            svc_type_db = self._get_service_type(context, id)
            svc_type_db['num_instances'] = svc_type_db['num_instances'] + 1
        return svc_type_db['num_instances']

    def decrease_service_type_refcount(self, context, id):
        """Decrease references count for a service type object

        This method should be invoked by plugins using the service
        type concept everytime an instance of an object associated
        with a given service type is removed
        """
        #TODO(salvatore-orlando): Devise a better solution than this
        #refcount mechanisms. Perhaps adding hooks into models which
        #use service types in order to enforce ref. integrity and cascade
        with context.session.begin(subtransactions=True):
            svc_type_db = self._get_service_type(context, id)
            if svc_type_db['num_instances'] == 0:
                LOG.warning(_("Number of instances for service type "
                              "'%s' is already 0."), svc_type_db['name'])
                return
            svc_type_db['num_instances'] = svc_type_db['num_instances'] - 1
        return svc_type_db['num_instances']
