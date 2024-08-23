.. _ovn_tools:

OVN Tools
=========

This document offers details on Neutron tools available for assisting
with using the Open Virtual Network (OVN) backend.

Patches and Cherry-picks
------------------------

Overview
^^^^^^^^
As described in the
`ovn-migration blueprint <https://review.opendev.org/#/c/658414/19/specs/ussuri/ml2ovs-ovn-convergence.rst>`__,
Neutron's OVN ML2 plugin has merged to the Neutron repository as of the Ussuri
release. With that, special care must be taken to apply Neutron
changes to the proper stable branches of the networking-ovn repo.

.. note::

   These scripts are generic enough to work on any patch file, but
   particularly handy with the networking-ovn migration.


tools/files_in_patch.py
^^^^^^^^^^^^^^^^^^^^^^^
Use this to show files that are changed in a patch file.

.. code-block:: console

   $ # Make a patch to use as example
   $ git show > /tmp/commit.patch

   $ ./tools/files_in_patch.py /tmp/commit.patch | grep .py
   tools/download_gerrit_change.py
   tools/files_in_patch.py
   tools/migrate_names.py


tools/download_gerrit_change.py
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This tool is needed by ``migrate_names.py`` (see below), but it can be used
independently. Given a Gerrit change id, it will fetch the latest
patchset of the change from `review.opendev.org <https://review.opendev.org/>`__
as a patch file. The output can be stdout or an optional filename.

.. code-block:: console

   $ ./tools/download_gerrit_change.py --help
   Usage: download_gerrit_change.py [OPTIONS] GERRIT_CHANGE

   Options:
     -o, --output_patch TEXT  Output patch file. Default: stdout
     -g, --gerrit_url TEXT    The url to Gerrit server  [default:
                              https://review.opendev.org/]
     -t, --timeout INTEGER    Timeout, in seconds  [default: 10]
     --help                   Show this message and exit.

   $ ./tools/download_gerrit_change.py 698863 -o /tmp/change.patch
   $ ./tools/files_in_patch.py /tmp/change.patch
   networking_ovn/ml2/mech_driver.py
   networking_ovn/ml2/trunk_driver.py
   networking_ovn/tests/unit/ml2/test_mech_driver.py
   networking_ovn/tests/unit/ml2/test_trunk_driver.py


tools/migrate_names.py
^^^^^^^^^^^^^^^^^^^^^^

Use this tool to modify the name of the files in a patchfile so it can
be converted to/from the
`legacy networking-ovn <https://review.opendev.org/#/q/project:openstack/networking-ovn>`__ and
`Neutron <https://review.opendev.org/#/q/project:openstack/neutron>`__ repositories.

The mapping of how the files are renamed is based on ``migrate_names.txt``,
which is located in the same directory where ``migrate_names.py`` is installed.
That behavior can be modified via the ``--mapfile`` option. More information on
how the map is parsed is provided in the header section of that file.

.. code-block:: console

   $ ./tools/migrate_names.py --help
   Usage: migrate_names.py [OPTIONS]

   Options:
     -i, --input_patch TEXT    input_patch patch file or gerrit change
     -o, --output_patch TEXT   Output patch file. Default: stdout
     -m, --mapfile PATH        Data file that specifies mapping to be applied to
                               input  [default: /home/user/openstack/neutron.git
                               /tools/migrate_names.txt]
     --reverse / --no-reverse  Map filenames from networking-ovn to Neutron repo
     --help                    Show this message and exit.
   $ ./tools/migrate_names.py -i 701646 > /tmp/ovn_change.patch
   $ ./tools/migrate_names.py -o /tmp/reverse.patch -i /tmp/ovn_change.patch --reverse
   $ diff /tmp/reverse.patch /tmp/ovn_change.patch | grep .py
   < --- a/neutron/plugins/ml2/drivers/ovn/mech_driver/mech_driver.py
   < +++ b/neutron/plugins/ml2/drivers/ovn/mech_driver/mech_driver.py
   > --- a/networking_ovn/ml2/mech_driver.py
   > +++ b/networking_ovn/ml2/mech_driver.py
   <... snip ...>

   $ ./tools/files_in_patch.py /tmp/ovn_change.patch
   networking_ovn/ml2/mech_driver.py
   networking_ovn/ml2/trunk_driver.py
   networking_ovn/tests/unit/ml2/test_mech_driver.py
   networking_ovn/tests/unit/ml2/test_trunk_driver.py

