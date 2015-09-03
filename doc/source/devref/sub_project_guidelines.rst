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

Oslo Incubator
~~~~~~~~~~~~~~

Don't ever reuse neutron code that comes from oslo-incubator in your
subprojects. For neutron repository, the code is usually located under the
following path: neutron.openstack.common.*

If you need any oslo-incubator code in your repository, copy it into your
repository from oslo-incubator and then use it from there.

Neutron team does not maintain any backwards compatibility strategy for the
code subtree and can break anyone who relies on it at any time.

Requirements
------------

Neutron dependency
~~~~~~~~~~~~~~~~~~

Subprojects usually depend on neutron repositories, by using -e git://...
schema to define such a dependency. The dependency *must not* be present in
requirements lists though, and instead belongs to tox.ini deps section. This is
because next pbr library releases do not guarantee -e git://... dependencies
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
<https://review.openstack.org/#/c/215671/>`_.

Stable branches
---------------

Stable branches for libraries should be created at the same time when
corresponding neutron stable branches are cut off. This is to avoid situations
when a postponed cut-off results in a stable branch that contains some patches
that belong to the next release. This would require reverting patches, and this
is something you should avoid.

Make sure your neutron dependency uses corresponding stable branch for neutron,
not master.

Note that to keep requirements in sync with core neutron repositories in stable
branches, you should make sure that your project is registered in
openstack/requirements:projects.txt *for the branch in question*.

Subproject stable branches are supervised by horizontal `neutron-stable-maint
team <https://review.openstack.org/#/admin/groups/539,members>`_.

More info on stable branch process can be found on `the following page
<https://wiki.openstack.org/wiki/StableBranch>`_.

Releases
--------

It is suggested that sub-projects release new tarballs on PyPI from time to
time, especially for stable branches. It will make the life of packagers and
other consumers of your code easier.

It is highly suggested that you do not strip pieces of the source tree (tests,
executables, tools) before releasing on PyPI: those missing pieces may be
needed to validate the package, or make the packaging easier or more complete.
As a rule of thumb, don't strip anything from the source tree unless completely
needed.

Sub-Project Release Process
~~~~~~~~~~~~~~~~~~~~~~~~~~~

To release a sub-project, follow the following steps:

* Only members of the `neutron-release
  <https://review.openstack.org/#/admin/groups/150,members>`_ gerrit group can
  do releases. Make sure you talk to a member of neutron-release to perform
  your release.
* For projects which have not moved to post-versioning, we need to push an
  alpha tag to avoid pbr complaining. The neutron-release group will handle
  this.
* Modify setup.cfg to remove the version (if you have one), which moves your
  project to post-versioning, similar to all the other Neutron projects. You
  can skip this step if you don't have a version in setup.cfg.
* Have neutron-release push the tag to gerrit.
* Have neutron-release `tag the release
  <http://docs.openstack.org/infra/manual/drivers.html#tagging-a-release>`_,
  which will release the code to PyPi.
