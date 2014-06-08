# Copyright 2012 New Dream Network, LLC (DreamHost)
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
# @author: Mark McClain, DreamHost

from logging import config as logging_config

from alembic import context
from sqlalchemy import create_engine, pool

from neutron.db import model_base
from neutron.openstack.common import importutils


DATABASE_QUOTA_DRIVER = 'neutron.extensions._quotav2_driver.DbQuotaDriver'

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config
neutron_config = config.neutron_config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
logging_config.fileConfig(config.config_file_name)

plugin_class_path = neutron_config.core_plugin
active_plugins = [plugin_class_path]
active_plugins += neutron_config.service_plugins

for class_path in active_plugins:
    importutils.import_class(class_path)

# set the target for 'autogenerate' support
target_metadata = model_base.BASEV2.metadata


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with either a URL
    or an Engine.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    kwargs = dict()
    if neutron_config.database.connection:
        kwargs['url'] = neutron_config.database.connection
    else:
        kwargs['dialect_name'] = neutron_config.database.engine
    context.configure(**kwargs)

    with context.begin_transaction():
        context.run_migrations(active_plugins=active_plugins,
                               options=build_options())


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    engine = create_engine(
        neutron_config.database.connection,
        poolclass=pool.NullPool)

    connection = engine.connect()
    context.configure(
        connection=connection,
        target_metadata=target_metadata
    )

    try:
        with context.begin_transaction():
            context.run_migrations(active_plugins=active_plugins,
                                   options=build_options())
    finally:
        connection.close()


def build_options():
    return {'folsom_quota_db_enabled': is_db_quota_enabled()}


def is_db_quota_enabled():
    return neutron_config.QUOTAS.quota_driver == DATABASE_QUOTA_DRIVER


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
