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


Sub-Project Guidelines
======================

This document provides guidance for those who maintain projects that consume
main neutron or neutron advanced services repositories as a dependency. It is
not meant to describe projects that are not tightly coupled with Neutron code.

Code Reuse
----------

At all times, avoid using any Neutron symbols that are explicitly marked as
private (those have an underscore at the start of their names).

Try to avoid copy pasting the code from Neutron to extend it. Instead, rely on
enormous number of different plugin entry points provided by Neutron (L2 agent
extensions, API extensions, service plugins, core plugins, ML2 mechanism
drivers, etc.)

Requirements
------------

Neutron dependency
~~~~~~~~~~~~~~~~~~

Subprojects usually depend on neutron repositories, by using -e https://...
schema to define such a dependency. The dependency *must not* be present in
requirements lists though, and instead belongs to tox.ini deps section. This is
because next pbr library releases do not guarantee -e https://... dependencies
will work.

You may still put some versioned neutron dependency in your requirements list
to indicate the dependency for anyone who packages your subproject.

Explicit dependencies
~~~~~~~~~~~~~~~~~~~~~

Each neutron project maintains its own lists of requirements. Subprojects that
depend on neutron while directly using some of those libraries that neutron
maintains as its dependencies must not rely on the fact that neutron will pull
the needed dependencies for them. Direct library usage requires that this
library is mentioned in requirements lists of the subproject.

The reason to duplicate those dependencies is that neutron team does not stick
to any backwards compatibility strategy in regards to requirements lists, and
is free to drop any of those dependencies at any time, breaking anyone who
could rely on those libraries to be pulled by neutron itself.

Automated requirements updates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

At all times, subprojects that use neutron as a dependency should make sure
their dependencies do not conflict with neutron's ones.

Core neutron projects maintain their requirements lists by utilizing a
so-called proposal bot. To keep your subproject in sync with neutron, it is
highly recommended that you register your project in
openstack/requirements:projects.txt file to enable the bot to update
requirements for you.

Once a subproject opts in global requirements synchronization, it should enable
check-requirements jobs in project-config. For example, see `this patch
<https://review.opendev.org/#/c/215671/>`_.

Stable branches
---------------

Stable branches for subprojects should be created at the same time when
corresponding neutron stable branches are created. This is to avoid situations
when a postponed cut-off results in a stable branch that contains some patches
that belong to the next release. This would require reverting patches, and this
is something you should avoid.

Make sure your neutron dependency uses corresponding stable branch for neutron,
not master.

Note that to keep requirements in sync with core neutron repositories in stable
branches, you should make sure that your project is registered in
openstack/requirements:projects.txt *for the branch in question*.

Subproject stable branches are supervised by horizontal `neutron-stable-maint
team <https://review.opendev.org/#/admin/groups/539,members>`_.

More info on stable branch process can be found on `the following page
<http://docs.openstack.org/project-team-guide/stable-branches.html>`_.

Stable merge requirements
-------------------------

Merges into stable branches are handled by members of the `neutron-stable-maint
gerrit group <https://review.opendev.org/#/admin/groups/539,members>`_. The
reason for this is to ensure consistency among stable branches, and compliance
with policies for stable backports.

For sub-projects who participate in the Neutron Stadium effort and who also
create and utilize stable branches, there is an expectation around what is
allowed to be merged in these stable branches. The Stadium projects should be
following the stable branch policies as defined by on the `Stable Branch wiki
<http://docs.openstack.org/project-team-guide/stable-branches.html>`_. This
means that, among other things, no features are allowed to be backported into
stable branches.

.. _guideline-releases:

Releases
--------

It is suggested that sub-projects cut off new releases from time to time,
especially for stable branches. It will make the life of packagers and other
consumers of your code easier.

Sub-Project Release Process
~~~~~~~~~~~~~~~~~~~~~~~~~~~

All subproject releases are managed by `global OpenStack Release Managers team
<https://review.opendev.org/#/admin/groups/11,members>`_. The
`neutron-release team
<https://review.opendev.org/#/admin/groups/150,members>`_ handles only the
following operations:

* Make stable branches end of life

To release a sub-project, follow the following steps:

* For projects which have not moved to post-versioning, we need to push an
  alpha tag to avoid pbr complaining. A member of the neutron-release group
  will handle this.
* A sub-project owner should modify setup.cfg to remove the version (if you
  have one), which moves your project to post-versioning, similar to all the
  other Neutron projects. You can skip this step if you don't have a version in
  setup.cfg.
* A sub-project owner `proposes
  <https://opendev.org/openstack/releases/src/README.rst>`_ a patch
  to openstack/releases repository with the intended git hash. `The Neutron
  release liaison <https://wiki.openstack.org/wiki/CrossProjectLiaisons#Release_management>`_
  should be added in Gerrit to the list of reviewers for the patch.

  .. note::

     New major tag versions should conform to `SemVer <http://semver.org/>`_
     requirements, meaning no year numbers should be used as a major version.
     The switch to SemVer is advised at earliest convenience for all new major
     releases.

  .. note::

     Before Ocata, when releasing the very first release in a stable series, a
     sub-project owner would need to request a new stable branch creation
     during Gerrit review, but not anymore. `See the following email for more
     details <http://lists.openstack.org/pipermail/openstack-dev/2016-December/108923.html>`_.

* The Neutron release liaison votes with +1 for the openstack/releases patch.
* The releases will now be on PyPI. A sub-project owner should verify this by
  going to an URL similar to
  `this <https://pypi.org/simple/networking-odl>`_.
* A sub-project owner should next go to Launchpad and release this version
  using the "Release Now" button for the release itself.
* If a sub-project uses the "delay-release" option, a sub-project owner should
  update any bugs that were fixed with this release to "Fix Released" in
  Launchpad.  This step is not necessary if the sub-project uses the
  "direct-release" option, which is the default.  [#jeepyb_release_options]_
* The new release will be available on `OpenStack Releases
  <http://docs.openstack.org/releases/>`_.
* A sub-project owner should add the next milestone to the Launchpad series, or
  if a new series is required, create the new series and a new milestone.

.. note::

    You need to be careful when picking a git commit to base new releases on.
    In most cases, you'll want to tag the *merge* commit that merges your last
    commit in to the branch.  `This bug`__ shows an instance where this mistake
    was caught.  Notice the difference between the `incorrect commit`__ and the
    `correct one`__ which is the merge commit.  ``git log 6191994..22dd683
    --oneline`` shows that the first one misses a handful of important commits
    that the second one catches.  This is the nature of merging to master.

.. __: https://bugs.launchpad.net/neutron/+bug/1540633
.. __: https://github.com/openstack/networking-infoblox/commit/6191994515
.. __: https://github.com/openstack/networking-infoblox/commit/22dd683e1a


To make a branch end of life, follow the following steps:

* A member of neutron-release will abandon all open change reviews on
  the branch.
* A member of neutron-release will push an EOL tag on the branch.
  (eg. "icehouse-eol")
* A sub-project owner should request the infrastructure team to delete
  the branch by sending an email to the infrastructure mailing list, not by
  bothering the infrastructure team on IRC.
* A sub-project owner should tweak zuul jobs in project-config if any.

References
~~~~~~~~~~

.. [#jeepyb_release_options] http://lists.openstack.org/pipermail/openstack-dev/2015-December/081724.html
