..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Contributing new extensions to Neutron
======================================

Introduction
------------

Neutron has a pluggable architecture, with a number of extension points.
This documentation covers aspects relevant to contributing new Neutron
v2 core (aka monolithic) plugins, ML2 mechanism drivers, and L3 service
plugins. This document will initially cover a number of process-oriented
aspects of the contribution process, and proceed to provide a how-to guide
that shows how to go from 0 LOC's to successfully contributing new
extensions to Neutron. In the remainder of this guide, we will try to
use practical examples as much as we can so that people have working
solutions they can start from.

This guide is for a developer who wants to have a degree of visibility
within the OpenStack Networking project. If you are a developer who
wants to provide a Neutron-based solution without interacting with the
Neutron community, you are free to do so, but you can stop reading now,
as this guide is not for you.

Plugins and drivers for non-reference implementations are known as
"third-party" code. This includes code for supporting vendor products, as well
as code for supporting open-source networking implementations.

Before the Kilo release these plugins and drivers were included in the Neutron
tree. During the Kilo cycle the third-party plugins and drivers underwent the
first phase of a process called decomposition. During this phase, each plugin
and driver moved the bulk of its logic to a separate git repository, while
leaving a thin "shim" in the neutron tree together with the DB models and
migrations (and perhaps some config examples).

During the Liberty cycle the decomposition concept was taken to its conclusion
by allowing third-party code to exist entirely out of tree. Further extension
mechanisms have been provided to better support external plugins and drivers
that alter the API and/or the data model.

In the Mitaka cycle we will **require** all third-party code to be moved out of
the neutron tree completely.

'Outside the tree' can be anything that is publicly available: it may be a repo
on opendev.org for instance, a tarball, a pypi package, etc. A
plugin/drivers maintainer team self-governs in order to promote sharing, reuse,
innovation, and release of the 'out-of-tree' deliverable. It should not be
required for any member of the core team to be involved with this process,
although core members of the Neutron team can participate in whichever capacity
is deemed necessary to facilitate out-of-tree development.

This guide is aimed at you as the maintainer of code that integrates with
Neutron but resides in a separate repository.


Contribution Process
--------------------

If you want to extend OpenStack Networking with your technology, and you want
to do it within the visibility of the OpenStack project, follow the guidelines
and examples below. We'll describe best practices for:

* Design and Development;
* Testing and Continuous Integration;
* Defect Management;
* Backport Management for plugin specific code;
* DevStack Integration;
* Documentation;

Once you have everything in place you may want to add your project to the list
of Neutron sub-projects. See :ref:`add-remove-projects-to-stadium`
for details.


Design and Development
----------------------

Assuming you have a working repository, any development to your own repo does
not need any blueprint, specification or bugs against Neutron. However, if your
project is a part of the Neutron Stadium effort, you are expected to
participate in the principles of the Four Opens, meaning your design should be
done in the open. Thus, it is encouraged to file documentation for changes in
your own repository.

If your code is hosted on opendev.org then the gerrit review system is
automatically provided. Contributors should follow the review guidelines
similar to those of Neutron. However, you as the maintainer have the
flexibility to choose who can approve/merge changes in your own repo.

It is recommended (but not required,
see :doc:`policies <policies/thirdparty-ci>`)
that you set up a third-party CI system. This will provide a vehicle for
checking the third-party code against Neutron changes. See `Testing and
Continuous Integration`_ below for more detailed recommendations.

Design documents can still be supplied in form of Restructured Text (RST)
documents, within the same third-party library repo. If changes to the common
Neutron code are required, an :ref:`RFE <request-for-feature-enhancement>`
may need to be filed. However, every case is different and you are invited to
seek guidance from Neutron core reviewers about what steps to follow.


Testing and Continuous Integration
----------------------------------

The following strategies are recommendations only, since third-party CI testing
is not an enforced requirement. However, these strategies are employed by the
majority of the plugin/driver contributors that actively participate in the
Neutron development community, since they have learned from experience how
quickly their code can fall out of sync with the rapidly changing Neutron core
code base.

* You should run unit tests in your own external library (e.g. on
  opendev.org where Jenkins setup is for free).

* Your third-party CI should validate third-party integration with Neutron via
  functional testing. The third-party CI is a communication mechanism. The
  objective of this mechanism is as follows:

  * it communicates to you when someone has contributed a change that
    potentially breaks your code. It is then up to you maintaining the affected
    plugin/driver to determine whether the failure is transient or real, and
    resolve the problem if it is.
  * it communicates to a patch author that they may be breaking a plugin/driver.
    If they have the time/energy/relationship with the maintainer of the
    plugin/driver in question, then they can (at their discretion) work to
    resolve the breakage.
  * it communicates to the community at large whether a given plugin/driver
    is being actively maintained.
  * A maintainer that is perceived to be responsive to failures in their
    third-party CI jobs is likely to generate community goodwill.

  It is worth noting that if the plugin/driver repository is hosted on
  opendev.org, due to current openstack-infra limitations, it is not
  possible to have third-party CI systems participating in the gate pipeline
  for the repo. This means that the only validation provided during the merge
  process to the repo is through unit tests. Post-merge hooks can still be
  exploited to provide third-party CI feedback, and alert you of potential
  issues. As mentioned above, third-party CI systems will continue to validate
  Neutron core commits. This will allow them to detect when incompatible
  changes occur, whether they are in Neutron or in the third-party repo.


Defect Management
-----------------

Bugs affecting third-party code should *not* be filed in the Neutron project on
launchpad. Bug tracking can be done in any system you choose, but by creating a
third-party project in launchpad, bugs that affect both Neutron and your code
can be more easily tracked using launchpad's "also affects project" feature.

Security Issues
~~~~~~~~~~~~~~~

Here are some answers to how to handle security issues in your repo, taken
from `this mailing list message
<http://lists.openstack.org/pipermail/openstack-dev/2015-July/068617.html>`_:

- How should security your issues be managed?

The OpenStack Vulnerability Management Team (VMT) follows a `documented process
<https://security.openstack.org/vmt-process.html>`_ which can basically be
reused by any project-team when needed.

- Should the OpenStack security team be involved?

The OpenStack VMT directly oversees vulnerability reporting and disclosure for
a `subset of OpenStack source code repositories
<https://wiki.openstack.org/wiki/Security_supported_projects>`_.  However, they
are still quite happy to answer any questions you might have about
vulnerability management for your own projects even if they're not part of that
set. Feel free to reach out to the VMT in public or in private.

Also, the VMT is an autonomous subgroup of the much larger `OpenStack Security
project-team
<https://governance.openstack.org/tc/reference/projects/security.html>`_. They're a
knowledgeable bunch and quite responsive if you want to get their opinions or
help with security-related issues (vulnerabilities or otherwise).

- Does a CVE need to be filed?

It can vary widely. If a commercial distribution such as Red Hat is
redistributing a vulnerable version of your software, then they may assign one
anyway even if you don't request one yourself. Or the reporter may request one;
the reporter may even be affiliated with an organization who has already
assigned/obtained a CVE before they initiate contact with you.

- Do the maintainers need to publish OSSN or equivalent documents?

OpenStack Security Advisories (OSSA) are official publications of the OpenStack
VMT and only cover VMT-supported software. OpenStack Security Notes (OSSN) are
published by editors within the OpenStack Security project-team on more general
security topics and may even cover issues in non-OpenStack software commonly
used in conjunction with OpenStack, so it's at their discretion as to whether
they would be able to accommodate a particular issue with an OSSN.

However, these are all fairly arbitrary labels, and what really matters in the
grand scheme of things is that vulnerabilities are handled seriously, fixed
with due urgency and care, and announced widely -- not just on relevant
OpenStack mailing lists but also preferably somewhere with broader distribution
like the `Open Source Security mailing list
<http://oss-security.openwall.org/wiki/mailing-lists/oss-security>`_. The goal
is to get information on your vulnerabilities, mitigating measures and fixes
into the hands of the people using your software in a timely manner.

- Anything else to consider here?

The OpenStack VMT is in the process of trying to reinvent itself so that it can
better scale within the context of the "Big Tent." This includes making sure
the policy/process documentation is more consumable and reusable even by
project-teams working on software outside the scope of our charter. It's a work
in progress, and any input is welcome on how we can make this function well for
everyone.


Backport Management Strategies
------------------------------

This section applies only to third-party maintainers who had code in the
Neutron tree during the Kilo and earlier releases. It will be obsolete once the
Kilo release is no longer supported.

If a change made to out-of-tree third-party code needs to be back-ported to
in-tree code in a stable branch, you may submit a review without a
corresponding master branch change. The change will be evaluated by core
reviewers for stable branches to ensure that the backport is justified and that
it does not affect Neutron core code stability.


DevStack Integration Strategies
-------------------------------

When developing and testing a new or existing plugin or driver, the aid provided
by DevStack is incredibly valuable: DevStack can help get all the software bits
installed, and configured correctly, and more importantly in a predictable way.
For DevStack integration there are a few options available, and they may or may not
make sense depending on whether you are contributing a new or existing plugin or
driver.

If you are contributing a new plugin, the approach to choose should be based on
`Extras.d Hooks' externally hosted plugins
<https://docs.openstack.org/devstack/latest/plugins.html#extras-d-hooks>`_.
With the extra.d hooks, the DevStack integration is co-located with the
third-party integration library, and it leads to the greatest level of
flexibility when dealing with DevStack based dev/test deployments.

One final consideration is worth making for third-party CI setups: if `Devstack
Gate <https://opendev.org/openstack/devstack-gate>`_ is used,
it does provide hook functions that can be executed at specific times of the
devstack-gate-wrap script run.  For example, the `Neutron Functional job
<https://opendev.org/openstack/project-config/tree/jenkins/jobs/neutron.yaml>`_
uses them. For more details see `devstack-vm-gate-wrap.sh
<https://opendev.org/openstack/devstack-gate/tree/devstack-vm-gate-wrap.sh>`_.


Documentation
-------------

For a layout of the how the documentation directory is structured see the
`effective neutron guide <effective_neutron.html>`_


Project Initial Setup
---------------------

The how-to below assumes that the third-party library will be hosted on
opendev.org. This lets you tap in the entire OpenStack CI infrastructure
and can be a great place to start from to contribute your new or existing
driver/plugin. The list of steps below are summarized version of what you can
find on http://docs.openstack.org/infra/manual/creators.html. They are meant to
be the bare minimum you have to complete in order to get you off the ground.

* Create a public repository: this can be a personal opendev.org repo or any
  publicly available git repo, e.g. ``https://github.com/john-doe/foo.git``. This
  would be a temporary buffer to be used to feed the one on opendev.org.
* Initialize the repository: if you are starting afresh, you may *optionally*
  want to use cookiecutter to get a skeleton project. You can learn how to use
  cookiecutter on https://opendev.org/openstack-dev/cookiecutter.
  If you want to build the repository from an existing Neutron module, you may
  want to skip this step now, build the history first (next step), and come back
  here to initialize the remainder of the repository with other files being
  generated by the cookiecutter (like tox.ini, setup.cfg, setup.py, etc.).
* Create a repository on opendev.org. For
  this you need the help of the OpenStack infra team. It is worth noting that
  you only get one shot at creating the repository on opendev.org. This
  is the time you get to choose whether you want to start from a clean slate,
  or you want to import the repo created during the previous step. In the
  latter case, you can do so by specifying the upstream section for your
  project in project-config/gerrit/project.yaml.  Steps are documented on the
  `Repository Creator's Guide
  <http://docs.openstack.org/infra/manual/creators.html>`_.
* Ask for a Launchpad user to be assigned to the core team created. Steps are
  documented in `this section
  <http://docs.openstack.org/infra/manual/creators.html#update-the-gerrit-group-members>`_.
* Fix, fix, fix: at this point you have an external base to work on. You can
  develop against the new opendev.org project, the same way you work with
  any other OpenStack project: you have pep8, docs, and python27 CI jobs that
  validate your patches when posted to Gerrit. For instance, one thing you
  would need to do is to define an entry point for your plugin or driver in
  your own setup.cfg similarly as to how it is done in the `setup.cfg for ODL
  <https://opendev.org/openstack/networking-odl/tree/setup.cfg#n31>`_.
* Define an entry point for your plugin or driver in setup.cfg
* Create third-party CI account: if you do not already have one, follow
  instructions for `third-party CI
  <http://docs.openstack.org/infra/system-config/third_party.html>`_ to get
  one.

Internationalization support
----------------------------

OpenStack is committed to broad international support.
Internationalization (I18n) is one of important areas to make OpenStack ubiquitous.
Each project is recommended to support i18n.

This section describes how to set up translation support.
The description in this section uses the following variables:

* repository : ``openstack/${REPOSITORY}`` (e.g., ``openstack/networking-foo``)
* top level python path : ``${MODULE_NAME}`` (e.g., ``networking_foo``)

oslo.i18n
~~~~~~~~~

* Each subproject repository should have its own oslo.i18n integration
  wrapper module ``${MODULE_NAME}/_i18n.py``. The detail is found at
  https://docs.openstack.org/oslo.i18n/latest/user/usage.html.

  .. note::

     **DOMAIN** name should match your **module** name ``${MODULE_NAME}``.

* Import ``_()`` from your ``${MODULE_NAME}/_i18n.py``.

  .. warning::

     Do not use ``_()`` in the builtins namespace which is
     registered by **gettext.install()** in ``neutron/__init__.py``.
     It is now deprecated as described in oslo.18n documentation.

Setting up translation support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You need to create or edit the following files to start translation support:

* setup.cfg
* babel.cfg

We have a good example for an oslo project at
https://review.opendev.org/#/c/98248/.

Add the following to ``setup.cfg``::

    [extract_messages]
    keywords = _ gettext ngettext l_ lazy_gettext
    mapping_file = babel.cfg
    output_file = ${MODULE_NAME}/locale/${MODULE_NAME}.pot

    [compile_catalog]
    directory = ${MODULE_NAME}/locale
    domain = ${MODULE_NAME}

    [update_catalog]
    domain = ${MODULE_NAME}
    output_dir = ${MODULE_NAME}/locale
    input_file = ${MODULE_NAME}/locale/${MODULE_NAME}.pot

Note that ``${MODULE_NAME}`` is used in all names.

Create ``babel.cfg`` with the following contents::

    [python: **.py]

Enable Translation
~~~~~~~~~~~~~~~~~~

To update and import translations, you need to make a change in project-config.
A good example is found at https://review.opendev.org/#/c/224222/.
After doing this, the necessary jobs will be run and push/pull a
message catalog to/from the translation infrastructure.

Integrating with the Neutron system
-----------------------------------

Configuration Files
~~~~~~~~~~~~~~~~~~~

The ``data_files`` in the ``[files]`` section of ``setup.cfg`` of Neutron shall
not contain any third-party references. These shall be located in the same
section of the third-party repo's own ``setup.cfg`` file.

* Note: Care should be taken when naming sections in configuration files. When
  the Neutron service or an agent starts, oslo.config loads sections from all
  specified config files. This means that if a section [foo] exists in multiple
  config files, duplicate settings will collide. It is therefore recommended to
  prefix section names with a third-party string, e.g. [vendor_foo].

Since Mitaka, configuration files are not maintained in the git repository but
should be generated as follows::

``tox -e genconfig``

If a 'tox' environment is unavailable, then you can run the following script
instead to generate the configuration files::

./tools/generate_config_file_samples.sh

It is advised that subprojects do not keep their configuration files in their
respective trees and instead generate them using a similar approach as Neutron
does.

**ToDo: Inclusion in OpenStack documentation?**
    Is there a recommended way to have third-party config options listed in the
    configuration guide in docs.openstack.org?


Database Models and Migrations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A third-party repo may contain database models for its own tables. Although
these tables are in the Neutron database, they are independently managed
entirely within the third-party code. Third-party code shall **never** modify
neutron core tables in any way.

Each repo has its own *expand* and *contract* `alembic migration branches
<alembic_migrations.html#migration-branches>`_. A third-party repo's alembic
migration branches may operate only on tables that are owned by the repo.

* Note: Care should be taken when adding new tables. To prevent collision of
  table names it is **required** to prefix them with a vendor/plugin string.

* Note: A third-party maintainer may opt to use a separate database for their
  tables. This may complicate cases where there are foreign key constraints
  across schemas for DBMS that do not support this well. Third-party maintainer
  discretion advised.

The database tables owned by a third-party repo can have references to fields
in neutron core tables. However, the alembic branch for a plugin/driver repo
shall never update any part of a table that it does not own.

**Note: What happens when a referenced item changes?**

* **Q:** If a driver's table has a reference (for example a foreign key) to a
  neutron core table, and the referenced item is changed in neutron, what
  should you do?

* **A:** Fortunately, this should be an extremely rare occurrence. Neutron core
  reviewers will not allow such a change unless there is a very carefully
  thought-out design decision behind it. That design will include how to
  address any third-party code affected. (This is another good reason why you
  should stay actively involved with the Neutron developer community.)

The ``neutron-db-manage`` alembic wrapper script for neutron detects alembic
branches for installed third-party repos, and the upgrade command automatically
applies to all of them. A third-party repo must register its alembic migrations
at installation time. This is done by providing an entrypoint in setup.cfg as
follows:

For a third-party repo named ``networking-foo``, add the alembic_migrations
directory as an entrypoint in the ``neutron.db.alembic_migrations`` group::

    [entry_points]
    neutron.db.alembic_migrations =
        networking-foo = networking_foo.db.migration:alembic_migrations

**ToDo: neutron-db-manage autogenerate**
    The alembic autogenerate command needs to support branches in external
    repos. Bug #1471333 has been filed for this.


DB Model/Migration Testing
~~~~~~~~~~~~~~~~~~~~~~~~~~

Here is a :doc:`template functional test <testing/template_model_sync_test>`
third-party maintainers can use to develop tests for model-vs-migration sync in
their repos. It is recommended that each third-party CI sets up such a test,
and runs it regularly against Neutron master.

Entry Points
~~~~~~~~~~~~

The `Python setuptools <https://pythonhosted.org/setuptools>`_ installs all
entry points for packages in one global namespace for an environment. Thus each
third-party repo can define its package's own ``[entry_points]`` in its own
``setup.cfg`` file.

For example, for the ``networking-foo`` repo::

    [entry_points]
    console_scripts =
        neutron-foo-agent = networking_foo.cmd.eventlet.agents.foo:main
    neutron.core_plugins =
        foo_monolithic = networking_foo.plugins.monolithic.plugin:FooPluginV2
    neutron.service_plugins =
        foo_l3 = networking_foo.services.l3_router.l3_foo:FooL3ServicePlugin
    neutron.ml2.type_drivers =
        foo_type = networking_foo.plugins.ml2.drivers.foo:FooType
    neutron.ml2.mechanism_drivers =
        foo_ml2 = networking_foo.plugins.ml2.drivers.foo:FooDriver
    neutron.ml2.extension_drivers =
        foo_ext = networking_foo.plugins.ml2.drivers.foo:FooExtensionDriver

* Note: It is advisable to include ``foo`` in the names of these entry points to
  avoid conflicts with other third-party packages that may get installed in the
  same environment.


API Extensions
~~~~~~~~~~~~~~

Extensions can be loaded in two ways:

#. Use the ``append_api_extensions_path()`` library API. This method is defined
   in ``neutron/api/extensions.py`` in the neutron tree.
#. Leverage the ``api_extensions_path`` config variable when deploying. See the
   example config file ``etc/neutron.conf`` in the neutron tree where this
   variable is commented.


Service Providers
~~~~~~~~~~~~~~~~~

If your project uses service provider(s) the same way VPNAAS does, you
specify your service provider in your ``project_name.conf`` file like so::

    [service_providers]
    # Must be in form:
    # service_provider=<service_type>:<name>:<driver>[:default][,...]

In order for Neutron to load this correctly, make sure you do the following in
your code::

    from neutron.db import servicetype_db
    service_type_manager = servicetype_db.ServiceTypeManager.get_instance()
    service_type_manager.add_provider_configuration(
        YOUR_SERVICE_TYPE,
        pconf.ProviderConfiguration(YOUR_SERVICE_MODULE, YOUR_SERVICE_TYPE))

This is typically required when you instantiate your service plugin class.


Interface Drivers
~~~~~~~~~~~~~~~~~

Interface (VIF) drivers for the reference implementations are defined in
``neutron/agent/linux/interface.py``. Third-party interface drivers shall be
defined in a similar location within their own repo.

The entry point for the interface driver is a Neutron config option. It is up to
the installer to configure this item in the ``[default]`` section. For example::

    [default]
    interface_driver = networking_foo.agent.linux.interface.FooInterfaceDriver

**ToDo: Interface Driver port bindings.**
    ``VIF_TYPE_*`` constants in ``neutron_lib/api/definitions/portbindings.py`` should be
    moved from neutron core to the repositories where their drivers are
    implemented. We need to provide some config or hook mechanism for VIF types
    to be registered by external interface drivers. For Nova, selecting the VIF
    driver can be done outside of
    Neutron (using the new `os-vif python library
    <https://review.opendev.org/193668>`_?). Armando and Akihiro to discuss.


Rootwrap Filters
~~~~~~~~~~~~~~~~

If a third-party repo needs a rootwrap filter for a command that is not used by
Neutron core, then the filter shall be defined in the third-party repo.

For example, to add a rootwrap filters for commands in repo ``networking-foo``:

* In the repo, create the file:
  ``etc/neutron/rootwrap.d/foo.filters``

* In the repo's ``setup.cfg`` add the filters to data_files::

    [files]
    data_files =
        etc/neutron/rootwrap.d =
            etc/neutron/rootwrap.d/foo.filters


Extending python-neutronclient
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The maintainer of a third-party component may wish to add extensions to the
Neutron CLI client. Thanks to https://review.opendev.org/148318 this can now
be accomplished. See `Client Command Extensions
<client_command_extensions.html>`_.


Other repo-split items
~~~~~~~~~~~~~~~~~~~~~~

(These are still TBD.)

* Splitting policy.json? **ToDo** Armando will investigate.

* Generic instructions (or a template) for installing an out-of-tree plugin or
  driver for Neutron. Possibly something for the networking guide, and/or a
  template that plugin/driver maintainers can modify and include with their
  package.
