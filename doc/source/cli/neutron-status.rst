.. This file is manually generated, unlike many of the other chapters.

==============
neutron-status
==============

The :command:`neutron-status` provides routines for checking the status of
Neutron deployment.

.. _neutron-status_usage:

neutron-status usage
~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-status [-h] [--config-dir DIR] [--config-file PATH]
                         <category> <command>

Categories are:

* ``upgrade``

Detailed descriptions are below.

You can also run with a category argument such as ``upgrade`` to see a list of
all commands in that category::

    neutron-status upgrade

These sections describe the available categories and arguments for
:command:`neutron-status`.

Command details
---------------

``neutron-status upgrade check``
  Performs a release-specific readiness check before restarting services
  with new code. This command expects to have complete configuration and access
  to databases and services.

  **Return Codes**

  .. list-table::
     :widths: 20 80
     :header-rows: 1

     * - Return code
       - Description
     * - 0
       - All upgrade readiness checks passed successfully and there is nothing
         to do.
     * - 1
       - At least one check encountered an issue and requires further
         investigation. This is considered a warning but the upgrade may be OK.
     * - 2
       - There was an upgrade status check failure that needs to be
         investigated. This should be considered something that stops an
         upgrade.
     * - 255
       - An unexpected error occurred.

  **History of Checks**

  **21.0.0 (Ussuri)**

  * A Check was added for NIC Switch agents to ensure nodes are running with
    kernel 3.13 or newer. This check serves as a notification for operators
    to ensure this requirement is fullfiled on relevant nodes.
