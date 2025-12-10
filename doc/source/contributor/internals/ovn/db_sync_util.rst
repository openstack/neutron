.. _ovn_db_sync_util:

===========================================================================
Synchronization of the Neutron and OVN Databases (neutron-ovn-db-sync-util)
===========================================================================

Consistency of the data between Neutron and OVN databases, how important it is
and what are the problems and potential solutions to ensure it are described in
the :ref:`database_consistency` document.
Additionally to all what is described there, Neutron provides CLI tool
`neutron-ovn-db-sync-util` which can be used by the cloud operator to sync OVN
database with the data stored in Neutron DB.

Usage
-----

The ``neutron-ovn-db-sync-util`` CLI tool is used to synchronize the OVN
Northbound and Southbound databases with the Neutron database.
This tool should be used ad-hoc, for example when inconsistencies between
databases are detected.

Basic usage::

    neutron-ovn-db-sync-util --config-file /etc/neutron/neutron.conf \
                             --config-file /etc/neutron/plugins/ml2/ml2_conf.ini

The tool supports several command-line options:

* ``--config-file``: Specify the configuration file(s) to use. Multiple config
  files can be specified. If no config file is provided, the tool will attempt
  to load configuration from ``/etc/neutron/neutron.conf``.

* ``--ovn-ovn_nb_connection``: OVN Northbound database connection string
  (usually configured in ml2_conf.ini).

* ``--ovn-ovn_sb_connection``: OVN Southbound database connection string
  (usually configured in ml2_conf.ini).

* ``--ovn-sync_mode``: Synchronization mode to use. Available modes:

  * ``log``: Only log inconsistencies without making any changes
  * ``repair``: Log inconsistencies and repair them by updating OVN database
  * ``migrate``: Run in migration mode for OVS to OVN migration (runs as
    repair mode in the synchronizer)

* ``--sync_plugin``: Specify a particular sync plugin to run. If not specified,
  all registered sync plugins will be loaded and executed.

* ``--migration_plugin``: Specify a particular migration plugin to run during
  OVS to OVN migration. If not specified, all registered migration plugins will
  be loaded and executed.

Example - Running in log mode to check for inconsistencies::

    neutron-ovn-db-sync-util --config-file /etc/neutron/neutron.conf \
                             --config-file /etc/neutron/plugins/ml2/ml2_conf.ini \
                             --ovn-sync_mode log

Example - Running in repair mode to fix inconsistencies::

    neutron-ovn-db-sync-util --config-file /etc/neutron/neutron.conf \
                             --config-file /etc/neutron/plugins/ml2/ml2_conf.ini \
                             --ovn-sync_mode repair

.. important::

   When running the sync utility, it is strongly recommended to stop the
   neutron-server service to avoid race conditions where the server might
   be modifying the database while the sync tool is running.

Sync plugins
------------

Sync plugins are responsible for synchronizing specific aspects of the Neutron
database with the OVN databases. Neutron provides two built-in sync plugins:

* **OvnNbSynchronizer**: Synchronizes the OVN Northbound database
* **OvnSbSynchronizer**: Synchronizes the OVN Southbound database

Writing a custom sync plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Stadium projects or third-party plugins can provide their own sync plugins by
implementing a synchronizer class and registering it via setuptools entry
points.

To create a custom sync plugin:

1. Create a class that inherits from ``BaseOvnDbSynchronizer`` (defined in
   ``neutron_lib.ovn.db_sync``):

.. code-block:: python

    from neutron_lib.ovn import db_sync

    class CustomSynchronizer(db_sync.BaseOvnDbSynchronizer):
        """Custom synchronizer for my plugin."""

        # Specify required mechanism drivers
        _required_mechanism_drivers = ['mechanism-driver-required-by-project']

        # Specify required service plugins
        _required_service_plugins = ['service-plugin-required-by-project']

        # Specify required ML2 extension drivers
        _required_ml2_ext_drivers = ['ml2-extension-required-by-project']

        def __init__(self, core_plugin, ovn_driver, mode, is_maintenance=False):
            super().__init__(core_plugin, ovn_driver, mode, is_maintenance)
            # Initialize any plugin-specific resources

        def do_sync(self):
            """Implement the synchronization logic."""
            if self.mode == ovn_const.OVN_DB_SYNC_MODE_OFF:
                return

            # Your synchronization logic here
            # Example:
            ctx = context.get_admin_context()
            self.sync_my_resources(ctx)

        def sync_my_resources(self, ctx):
            """Sync specific resources."""
            # Compare Neutron DB with OVN DB
            # Log inconsistencies
            # If mode is REPAIR, fix the inconsistencies

2. Register the plugin via setuptools entry point in your ``setup.cfg``::

    [entry_points]
    neutron.ovn.db_sync =
        my-sync-plugin = my_neutron_plugin.ovn.db_sync:MyCustomSynchronizer

The entry point group must be ``neutron.ovn.db_sync`` for the plugin to be
discovered by the ``neutron-ovn-db-sync-util`` tool.

Key implementation guidelines
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* **Use class attributes for requirements**: Define
  ``_required_mechanism_drivers``, ``_required_service_plugins``, and
  ``_required_ml2_ext_drivers`` to ensure all necessary plugins and drivers are
  loaded before synchronization begins.

* **Implement do_sync() method**: This is the main entry point for your
  synchronization logic. The method should check the mode and act accordingly:

  * In ``log`` mode: Only log inconsistencies
  * In ``repair`` mode: Log and fix inconsistencies

* **Use transactions**: When making changes to OVN database, use transactions
  to ensure atomicity::

    with self.ovn_nb_api.transaction(check_error=True) as txn:
        txn.add(self.ovn_nb_api.some_operation(...))

* **Access OVN APIs**: The base class provides access to:

  * ``self.ovn_nb_api``: OVN Northbound API
  * ``self.ovn_sb_api``: OVN Southbound API
  * ``self.core_plugin``: Neutron core plugin
  * ``self.ovn_driver``: OVN mechanism driver
  * ``self.mode``: Current sync mode

OVS to OVN migration
--------------------

The ``neutron-ovn-db-sync-util`` tool supports migration from ML2/OVS to
ML2/OVN deployments. When run in ``migrate`` mode, the tool performs the
following:

1. Runs all synchronization plugins in ``repair`` mode to ensure the OVN
   databases are synchronized with Neutron.

2. Executes all registered migration plugins to perform ML2/OVS specific data
   transformations.

To run a migration::

    neutron-ovn-db-sync-util --config-file /etc/neutron/neutron.conf \
                             --config-file /etc/neutron/plugins/ml2/ml2_conf.ini \
                             --ovn-sync_mode migrate

The migration process:

1. First, the tool validates that the ML2 core plugin and OVN mechanism driver
   are properly configured.

2. It then loads all sync plugins and runs them in ``repair`` mode to
   synchronize the current state of Neutron with OVN.

3. After synchronization is complete, it loads and executes all migration
   plugins registered under the ``neutron.ovn.db_migration`` entry point.

.. warning::

   Migration is a one-time operation and should be carefully planned:

   * Stop all neutron-server instances before running migration
   * Backup your databases before starting
   * Test the migration in a development environment first
   * Monitor logs carefully during the migration process

Migration plugins
-----------------

Migration plugins handle the transformation of ML2/OVS specific data to ML2/OVN
format during the migration process. Unlike sync plugins which ensure
consistency, migration plugins perform one-time data transformations.

Writing a custom migration plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Stadium projects or third-party plugins that stored OVS-specific data in the
Neutron database may need to provide migration plugins to transform that data
for OVN compatibility.

To create a custom migration plugin:

1. Create a migration function that performs the necessary database
   transformations:

.. code-block:: python

    def migrate_my_plugin_data():
        """Migrate ML2/OVS specific data to ML2/OVN format.

        This function is called during the migration process and should
        handle the transformation of any plugin-specific data from OVS
        to OVN format.
        """
        LOG.info("Starting migration of my plugin data")

        # Access the database
        ctx = context.get_admin_context()

        # Perform data transformations
        # Example: Update table records, migrate configuration, etc.
        with db_api.CONTEXT_WRITER.using(ctx):
            # Your migration logic here
            pass

        LOG.info("Completed migration of my plugin data")

2. Register the migration function via setuptools entry point in your ``setup.cfg``::

    [entry_points]
    neutron.ovn.db_migration =
        my-migration-plugin = my_neutron_plugin.ovn.migration:migrate_my_plugin_data

The entry point group must be ``neutron.ovn.db_migration`` for the plugin to be
discovered during migration.

Key implementation guidelines
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* **Idempotency**: Migration functions should be idempotent - safe to run
  multiple times without causing issues if the migration is interrupted and
  restarted.

* **Error handling**: Use appropriate error handling and logging to track
  migration progress and handle failures gracefully.

* **Database transactions**: Use database context managers to ensure data
  integrity::

    with db_api.CONTEXT_WRITER.using(ctx):
        # Database modifications here

* **Logging**: Provide detailed logging at the start and completion of
  migration, as well as for any significant operations performed during the
  migration.

* **No return value needed**: Migration functions are called via
  ``ExtensionManager.map()`` and don't need to return any value.
