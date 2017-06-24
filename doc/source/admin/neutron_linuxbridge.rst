====================================
neutron-linuxbridge-cleanup utility
====================================

Description
~~~~~~~~~~~

Automated removal of empty bridges has been disabled to fix a race condition
between the Compute (nova) and Networking (neutron) services. Previously, it
was possible for a bridge to be deleted during the time when the only instance
using it was rebooted.

Usage
~~~~~

Use this script to remove empty bridges on compute nodes by running the
following command:

.. code-block:: console

   $ neutron-linuxbridge-cleanup

.. important::

   Do not use this tool when creating or migrating an instance as it
   throws an error when the bridge does not exist.

.. note::

   Using this script can still trigger the original race condition. Only
   run this script if you have evacuated all instances off a compute
   node and you want to clean up the bridges. In addition to evacuating
   all instances, you should fence off the compute node where you are going
   to run this script so new instances do not get scheduled on it.

