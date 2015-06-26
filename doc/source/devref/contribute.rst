Contributing new extensions to Neutron
======================================

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
In fact, from the Kilo release onwards, the Neutron core team propose that
additions to the codebase adopt a structure where the *monolithic plugins*,
*ML2 MechanismDrivers*, and *L3 service plugins* are integration-only
(called "vendor integration" hereinafter) to code that lives outside the
tree (called "vendor library" hereinafter); the same applies for any
vendor-specific agents. The only part that is to stay in the tree is the
agent 'main' (a small python file that imports agent code from the vendor
library and starts it). 'Outside the tree' can be anything that is publicly
available: it may be a stackforge repo for instance, a tarball, a pypi package,
etc. A plugin/drivers maintainer team self-governs in order to promote sharing,
reuse, innovation, and release of the 'out-of-tree' deliverable. It should not
be required for any member of the core team to be involved with this process,
although core members of the Neutron team can participate in whichever capacity
is deemed necessary to facilitate out-of-tree development.

Below, the following strategies will be documented:

* Design and Development;
* Testing and Continuous Integration;
* Defect Management;
* Backport Management for plugin specific code;
* DevStack Integration;
* Documentation;

This document will then provide a working example on how to contribute
new additions to Neutron.

Blueprint Spec Submission Strategy
----------------------------------

Provided contributors adhere to the abovementioned development footprint
they should not be required to follow the spec process for changes that
only affect their vendor integration and library. New contributions can
simply be submitted for code review, with the proviso that adequate
documentation and 3rd CI party is supplied at the time of the code
submission. For tracking purposes, the review itself can be tagged
with a Launchpad bug report. The bug should be marked as wishlist to
avoid complicating tracking of Neutron's primary deliverables. Design
documents can still be supplied in form of RST documents, within the same
vendor library repo. If substantial change to the common Neutron code are
required, a spec that targets common Neutron code will be required, however
every case is different and a contributor is invited to seek guidance from
the Neutron core team as to what steps to follow, and whether a spec or
a bug report is more suited for what a contributor needs to deliver.

Once again, for submitting the integration module to the Neutron codebase,
no spec is required.

Development Strategy
--------------------

* The following elements are suggested to be contributed in the tree
  for plugins and drivers (called vendor integration hereinafter):

  * Data models
  * Extension definitions
  * Configuration files
  * Requirements file targeting vendor code

* Things that do not remain in the tree (called vendor library hereinafter):

  * Vendor specific logic
  * Associated unit tests

The idea here would be to provide in-tree the plugin/driver code that
implements an API, but have it delegate to out-of-tree code for
backend-specific interactions. The vendor integration will then typically
involve minor passthrough/parsing of parameters, minor handling of DB objects
as well as handling of responses, whereas the vendor library will do the
heavylifting and implement the vendor-specific logic. The boundary between
the in-tree layer and the out-of-tree one should be defined by the contributor
while asking these types of questions:

  * If something changes in my backend, do I need to alter the integration
    layer drastically? Clearly, the less impact there is, the better the
    separation being achieved.
  * If I expose vendor details (e.g. protocols, auth, etc.), can I easily swap
    and replace the targeted backend (e.g. hardware with a newer version
    being supplied) without affecting the integration too much? Clearly, the
    more reusable the integration the better the separation.

As mentioned above, the vendor code *must* be available publicly, and a git
repository makes the most sense. By doing so, the module itself can be made
accessible using a pip requirements file. This file  should not be confused
with the Neutron requirements file that lists all common dependencies. Instead
it should be a file 'requirements.txt' that is located in neutron/plugins/pluginXXX/,
whose content is something along the lines of 'my_plugin_xxx_library>=X.Y.Z'.
Vendors are responsible for ensuring that their library does not depend on
libraries conflicting with global requirements, but it could depend on
libraries not included in the global requirements. Just as in Neutron's
main requirements.txt, it will be possible to pin the version of the vendor
library.

For instance, a vendor integration module can become as simple as one that
performs only the following:

* Registering config options
* Registering the plugin class
* Registering the models
* Registering the extensions

Testing Strategy
----------------

The testing process will be as follow:

* No unit tests for the vendor integration of plugins and drivers are deemed
  necessary. The expectation is that contributors would run unit test in their
  own external library (e.g. in stackforge where Jenkins setup is for free).
  For unit tests that validate the vendor library, it is the responsibility of
  the vendor to choose what CI system they see fit to run them. There is no
  need or requirement to use OpenStack CI resources if they do not want to.
  Having said that, it may be useful to provide coverage for the shim layer in
  the form of basic validation as done in `ODL <https://git.openstack.org/cgit/openstack/networking-odl/tree/networking_odl/tests/unit/ml2/test_mechanism_odl.py>`_ and `LBaaS A10 driver <https://git.openstack.org/cgit/openstack/neutron-lbaas/tree/neutron_lbaas/tests/unit/services/loadbalancer/drivers/a10networks/test_driver_v1.py>`_.

* 3rd Party CI will continue to validate vendor integration with Neutron via
  functional testing. 3rd Party CI is a communication mechanism. This objective
  of this mechanism is as follows:

  * it communicates to plugin/driver contributors when someone has contributed
    a change that is potentially breaking. It is then up to a given
    contributor maintaining the affected plugin to determine whether the
    failure is transient or real, and resolve the problem if it is.
  * it communicates to a patch author that they may be breaking a plugin/driver.
    If they have the time/energy/relationship with the maintainer of the
    plugin/driver in question, then they can (at their discretion) work to
    resolve the breakage.
  * it communicates to the community at large whether a given plugin/driver
    is being actively maintained.
  * A maintainer that is perceived to be responsive to failures in their
    3rd party CI jobs is likely to generate community goodwill.

  It is worth noting that if the vendor library is hosted on StackForge, due to
  current openstack-infra limitations, it is not possible to have 3rd party CI systems
  participating in the gate pipeline for the StackForge repo. This means that the only
  validation provided during the merge process to the StackForge repo is through unit
  tests. Post-merge hooks can still be exploited to provide 3rd party CI feedback, and
  alert the contributor/reviewer of potential issues. As mentioned above, 3rd party CI
  systems will continue to validate Neutron core commits. This will allow them to
  detect when incompatible changes occur, whether they are in Neutron or in the vendor
  library repo.

Review and Defect Management Strategies
---------------------------------------

The usual process applies to the code that is part of OpenStack Neutron. More
precisely:

* Bugs that affect vendor code can be filed against the Neutron integration,
  if the integration code is at fault. Otherwise, the code maintainer may
  decide to fix a bug without oversight, and update their requirements file
  to target a new version of their vendor library. It makes sense to
  require 3rd party CI for a given plugin/driver to pass when changing their
  dependency before merging to any branch (i.e. both master and stable branches).
* Vendor specific code should follow the same review guidelines as any other
  code in the tree. However, the maintainer has flexibility to choose who
  can approve/merge changes in this repo.

Backport Management Strategies
------------------------------

As outlined in the `Spec proposal <http://specs.openstack.org/openstack/neutron-specs/specs/kilo/core-vendor-decomposition.html>`_
all new plugins and drivers will have to follow the contribution model
described here. As for existing plugins and drivers, no in-tree features can
be merged until some progress has been done to make the solution adhere to
this model. That said, there is the question of critical fixes and/or backports
to `stable branches <https://wiki.openstack.org/wiki/StableBranch>`_. The possible
scenarios are:

* The decomposition just completed, we are in the cycle (X) where the decomposition
  initiated: in this case, the Neutron master branch no longer have the vendor
  library code, but the stable branch still does. Backports via straight
  cherry-picks may not be possible, or as easy, therefore a custom backport to
  stable could be deemed acceptable to Neutron's stable branches (e.g. stable/X-1
  and/or stable/X-2), as required.
* The decomposition is complete, we are in the next cycle where the
  decomposition work completed (X+1): backports will be done to the stable branch
  available of the vendor library (stable/X), and Neutron's stable branch
  (stable/X-1), as outlined in the previous step.
* The decomposition is complete, we are in two or more cycles after the
  decomposition work completed (X+2, or later). Backports will be done to the
  stable branch(s) available of the vendor library (stable/X, stable/X+1).
* The decomposition is in progress: as long as the vendor code is still in
  master, patches will need to go to master before a backport to stable.
  Acceptance will be determined on the scope of changes (based on both the
  amount of work and severity of the issue). In this case, the plugin or
  driver maintainer will need to ensure that the fix gets applied to the
  external repo, if necessary (to avoid missing it during the migration process).
* The decomposition has not started: in this case, depending on the issue,
  review attention from core members is best effort, and although there is no
  explicit rule to prevent them from merging to master, it is in the best interest
  of the maintainer to avoid introducing or modifying existing code that will
  ultimately be deprecated.

DevStack Integration Strategies
-------------------------------

When developing and testing a new or existing plugin or driver, the aid provided
by DevStack is incredibly valuable: DevStack can help get all the software bits
installed, and configured correctly, and more importantly in a predictable way.
For DevStack integration there are a few options available, and they may or may not
make sense depending on whether you are contributing a new or existing plugin or
driver.

If you are contributing a new plugin, the approach to choose should be based on
`Extras.d Hooks' externally hosted plugins <http://docs.openstack.org/developer/devstack/plugins.html#extras-d-hooks>`_.
With the extra.d hooks, the DevStack integration is colocated with the vendor integration
library, and it leads to the greatest level of flexibility when dealing with DevStack based
dev/test deployments.

Having said that, most Neutron plugins developed in the past likely already have
integration with DevStack in the form of `neutron_plugins <https://git.openstack.org/cgit/openstack-dev/devstack/tree/lib/neutron_plugins>`_.
If the plugin is being decomposed in vendor integration plus vendor library, it would
be necessary to adjust the instructions provided in the neutron_plugin file to pull the
vendor library code as a new dependency. For instance, the instructions below:

  ::

      INSTALL_FROM_REQUIREMENTS=$(trueorfalse True INSTALL_FROM_REQUIREMENTS)

      if [[ "$INSTALL_FROM_REQUIREMENTS" == "False" ]]; then
          git_clone $NEUTRON_LIB_REPO $NEUTRON_LIB_DIR $NEUTRON_LIB_BRANCH
          setup_package $NEUTRON_LIB_DIR
      else
          # Retrieve the package from the vendor library's requirements.txt
          plugin_package=$(cat $NEUTRON_LIB_REQUIREMENTS_FILE)
          pip_install "$plugin_package"
      fi

could be placed in 'neutron_plugin_configure_service', ahead of the service
configuration. An alternative could be under the `third_party section
<https://git.openstack.org/cgit/openstack-dev/devstack/tree/lib/neutron_thirdparty>`_,
if available. This solution can be similarly exploited for both monolithic
plugins or ML2 mechanism drivers. The configuration of the plugin or driver itself can be
done by leveraging the extensibility mechanisms provided by `local.conf <http://docs.openstack.org/developer/devstack/configuration.html>`_. In fact, since the .ini file for the vendor plugin or driver lives
in the Neutron tree, it is possible to do add the section below to local.conf:

  ::

     [[post-config|$THE_FILE_YOU_NEED_TO_CUSTOMIZE]]

     # Override your section config as you see fit
     [DEFAULT]
     verbose=True

Which in turn it is going to edit the file with the options outlined in the post-config
section.

The above mentioned approach, albeit valid, has the shortcoming of depending on DevStack's
explicit support for the plugin installation and configuration, and the plugin maintainer
is strongly encouraged to revise the existing DevStack integration, in order to evolve it
in an extras.d hooks based approach.

One final consideration is worth making for 3rd party CI setups: if `Devstack Gate
<https://git.openstack.org/cgit/openstack-infra/devstack-gate>`_ is used, it does provide hook
functions that can be executed at specific times of the devstack-gate-wrap script run.
For example, the `Neutron Functional job <https://git.openstack.org/cgit/openstack-infra/project-config/tree/jenkins/jobs/neutron.yaml>`_ uses them. For more details see `devstack-vm-gate-wrap.sh <https://git.openstack.org/cgit/openstack-infra/devstack-gate/tree/devstack-vm-gate-wrap.sh>`_.

Documentation Strategies
------------------------

It is the duty of the new contributor to provide working links that can be
referenced from the OpenStack upstream documentation.
#TODO(armax): provide more info, when available.

How-to
------

The how-to below assumes that the vendor library will be hosted on StackForge.
Stackforge lets you tap in the entire OpenStack CI infrastructure and can be
a great place to start from to contribute your new or existing driver/plugin.
The list of steps below are somewhat the tl;dr; version of what you can find
on http://docs.openstack.org/infra/manual/creators.html. They are meant to
be the bare minimum you have to complete in order to get you off the ground.

* Create a public repository: this can be a personal git.openstack.org repo or any
  publicly available git repo, e.g. ``https://github.com/john-doe/foo.git``. This
  would be a temporary buffer to be used to feed the StackForge one.
* Initialize the repository: if you are starting afresh, you may *optionally*
  want to use cookiecutter to get a skeleton project. You can learn how to use
  cookiecutter on https://git.openstack.org/cgit/openstack-dev/cookiecutter.
  If you want to build the repository from an existing Neutron module, you may
  want to skip this step now, build the history first (next step), and come back
  here to initialize the remainder of the repository with other files being
  generated by the cookiecutter (like tox.ini, setup.cfg, setup.py, etc.).
* Building the history: if you are contributing an existing driver/plugin,
  you may want to preserve the existing history. If not, you can go to the
  next step. To import the history from an existing project this is what
  you need to do:

  * Clone a copy of the neutron repository to be manipulated.
  * Go into the Neutron repo to be changed.
  * Execute file split.sh, available in ./tools, and follow instructions.

    ::

        git clone https://git.openstack.org/openstack/neutron.git
        cd neutron
        ./tools/split.sh
        # Sit and wait for a while, or grab a cup of your favorite drink

    At this point you will have the project pruned of everything else but
    the files you want to export, with their history. The next steps are:

  * Check out stable branches for the project: even though stable branches
    are not strictly necessary during the creation of the StackForge repository
    (as outlined in the next step below), they do not hurt, and it is
    recommended to keep them during the import process.
  * Add a remote that points to the repository created before.
  * (Optional) If the repository has already being initialized with
    cookiecutter, you need to pull first; if not, you can either push
    the existing commits/tags or apply and commit further changes to fix
    up the structure of repo the way you see fit.
  * Finally, push commits and tags to the public repository. If you followed
    theses instructions step-by-step, you will have a source repository
    that contains both a master and stable branches, as well as tags. Some
    of these steps are outlined below:

    ::

        git remote add <foo> https://github.com/john-doe/foo.git
        git pull foo master # OPTIONAL, if foo is non-empty
        git push --all foo && git push --tags foo

* Create a StackForge repository: for this you need the help of the OpenStack
  infra team. It is worth noting that you only get one shot at creating the
  StackForge repository. This is the time you get to choose whether you want
  to start from a clean slate, or you want to import the repo created during
  the previous step. In the latter case, you can do so by specifying the
  upstream section for your project in project-config/gerrit/project.yaml.
  Steps are documented on the
  `Repository Creator's Guide <http://docs.openstack.org/infra/manual/creators.html>`_.
* Ask for a Launchpad user to be assigned to the core team created. Steps are
  documented in
  `this section <http://docs.openstack.org/infra/manual/creators.html#update-the-gerrit-group-members>`_.
* Fix, fix, fix: at this point you have an external base to work on. You
  can develop against the new stackforge project, the same way you work
  with any other OpenStack project: you have pep8, docs, and python27 CI
  jobs that validate your patches when posted to Gerrit. For instance, one
  thing you would need to do is to define an entry point for your plugin
  or driver in your own setup.cfg similarly as to how it is done
  `here <https://git.openstack.org/cgit/openstack/networking-odl/tree/setup.cfg#n31>`_.
* Define an entry point for your plugin or driver in setup.cfg
* Create 3rd Party CI account: if you do not already have one, follow
  instructions for
  `3rd Party CI <http://docs.openstack.org/infra/system-config/third_party.html>`_ to get one.
* TODO(armax): ...


Decomposition progress chart
============================

The chart below captures the progress of the core-vendor-decomposition effort
for existing plugins and drivers at the time the decomp effort started. New
drivers and plugins are not required to be listed here. This chart is short
lived: once the effort is complete, this chart no longer needs to exist and
will be removed. The following aspects are captured:

* Name: the name of the project that implements a Neutron plugin or driver. The
  name is an internal target for links that point to source code, etc.
* Plugins/Drivers: whether the source code contains a core (aka monolithic)
  plugin, a set of ML2 drivers, and/or (service) plugins (or extensions) for
  firewall, vpn, and load balancers.
* Launchpad: whether the project is managed through Launchpad.
* PyPI: whether the project deliverables are available through PyPI.
* State: a code to represent the current state of the decomposition. Possible
  values are:

  * [A] External repo available, no code decomposition
  * [B] External repo available, partial code decomposition
  * [C] External repo available, code decomposition is complete
  * [D] Not deemed required. Driver is already bare-bone and decomposition
    effort is not considered justified. Assessment may change in the
    future.

  Absence of an entry for an existing plugin or driver means no active effort
  has been observed or potentially not required.
* Completed in: the release in which the effort is considered completed. Code
  completion can be deemed as such, if there is no overlap/duplication between
  what exists in the Neutron tree, and what it exists in the vendor repo.

+-------------------------------+-----------------------+-----------+------------------+---------+--------------+
| Name                          |    Plugins/Drivers    | Launchpad |       PyPI       |  State  | Completed in |
+===============================+=======================+===========+==================+=========+==============+
| freescale-nscs                |         ml2,fw        |    no     |       no         |   [D]   |              |
+-------------------------------+-----------------------+-----------+------------------+---------+--------------+
