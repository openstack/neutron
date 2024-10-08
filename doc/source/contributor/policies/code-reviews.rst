.. _code_review:

Code Reviews
============

Code reviews are a critical component of all OpenStack projects. Neutron
accepts patches from many diverse people with diverse backgrounds, employers,
and experience levels. Code reviews provide a way to enforce a level of
consistency across the project, and also allow for the careful on boarding
of contributions from new contributors.

Neutron Code Review Practices
-----------------------------
Neutron follows the `code review guidelines <https://wiki.openstack.org/wiki/ReviewChecklist>`_ as
set forth for all OpenStack projects. It is expected that all reviewers are
following the guidelines set forth on that page.

In addition to that, the following rules are to follow:

* Any change that requires a new feature from Neutron runtime dependencies
  requires special review scrutiny to make sure such a change does not break
  a supported platform (examples of those platforms are latest Ubuntu LTS or
  CentOS). Runtime dependencies include but are not limited to: kernel, daemons
  and tools as defined in ``oslo.rootwrap`` filter files, runlevel management
  systems, as well as other elements of Neutron execution environment.

  .. note::

     For some components, the list of supported platforms can be wider than
     usual. For example, Open vSwitch agent is expected to run successfully in
     Win32 runtime environment.

  #. All such changes must be tagged with ``UpgradeImpact`` in their commit
     messages.

  #. Reviewers are then advised to make an effort to check if the newly
     proposed runtime dependency is fulfilled on supported platforms.

  #. Specifically, reviewers and authors are advised to use existing gate and
     experimental platform specific jobs to validate those patches. To trigger
     experimental jobs, use the usual protocol (posting ``check experimental``
     comment in Gerrit). CI will then execute and report back a baseline of
     Neutron tests for platforms of interest and will provide feedback on the
     effect of the runtime change required.

  #. If review identifies that the proposed change would break a supported
     platform, advise to rework the patch so that it's no longer breaking the
     platform. One of the common ways of achieving that is gracefully falling
     back to alternative means on older platforms, another is hiding the new
     code behind a conditional, potentially controlled with a ``oslo.config``
     option.

     .. note::

        Neutron team retains the right to remove any platform conditionals in
        future releases. Platform owners are expected to accommodate in due
        course, or otherwise see their platforms broken. The team also retains
        the right to discontinue support for unresponsive platforms.

  #. The change should also include a new `sanity check
     <https://opendev.org/openstack/neutron/src/neutron/cmd/sanity/checks.py>`_
     that would help interested parties to identify their platform limitation
     in timely manner.

* Special attention should also be paid to changes in Neutron that can impact
  the Stadium and the wider family of networking-related projects
  (referred to as sub-projects below). These changes include:

  #. Renaming or removal of methods.
  #. Addition or removal of positional arguments.
  #. Renaming or removal of constants.

  To mitigate the risk of impacting the sub-projects with these changes, the
  following measures are suggested:

  #. Use of the online tool `codesearch <http://codesearch.openstack.org>`_ to
     ascertain how the proposed changes will affect the code of the
     sub-projects.
  #. Review the results of the non-voting check and 3rd party CI
     jobs executed by the sub-projects against the proposed change, which are
     returned by Zuul in the change's Gerrit page.

  When impacts are identified as a result of the above steps, every effort must
  be made to work with the affected sub-projects to resolve the issues.

* Any change that modifies or introduces a new API should have test coverage in
  neutron-tempest-plugin or tempest test suites. There should be at least one
  API test added for a new feature, but it is preferred that both API and
  scenario tests be added where it is appropriate.

  Scenario tests should cover not only the base level of new functionality, but
  also standard ways in which the functionality can be used. For example, if
  the feature adds a new kind of networking (like e.g. trunk ports) then tests
  should make sure that instances can use IPs provided by that networking,
  can be migrated, etc.

  It is also preferred that some negative test cases, like API tests to
  ensure that correct HTTP error is returned when wrong data is provided,
  will be added where it is appropriate.

* It is usually enough for any "mechanical" changes, like e.g. translation
  imports or imports of updated CI templates, to have only one +2 Code-Review
  vote to be approved. If there is any uncertainty about a specific patch, it
  is better to wait for review from another core reviewer before approving the
  patch.

.. _spec-review-practices:

Neutron Spec Review Practices
-----------------------------
In addition to code reviews, Neutron also maintains a BP specification git
repository. Detailed instructions for the use of this repository are provided
`here <https://wiki.openstack.org/wiki/Blueprints>`_.
It is expected that Neutron core team members are actively reviewing
specifications which are pushed out for review to the specification repository.
In addition, there is a neutron-drivers team, composed of a
handful of Neutron core reviewers, who can approve and merge Neutron specs.

Some guidelines around this process are provided below:

* Once a specification has been pushed, it is expected that it will not be
  approved for at least 3 days after a first Neutron core reviewer has reviewed
  it. This allows for additional cores to review the specification.
* For blueprints which the core team deems of High or Critical importance,
  core reviewers may be assigned based on their subject matter expertise.
* Specification priority will be set by the PTL with review by the core team
  once the specification is approved.

Tracking Review Statistics
--------------------------
Stackalytics provides some nice interfaces to track review statistics. The
links are provided below. These statistics are used to track not only Neutron
core reviewer statistics, but also to track review statistics
for potential future core members.

* `30 day review stats <https://www.stackalytics.io/report/contribution?module=neutron-group&project_type=openstack&days=30>`_
* `60 day review stats <https://www.stackalytics.io/report/contribution?module=neutron-group&project_type=openstack&days=60>`_
* `90 day review stats <https://www.stackalytics.io/report/contribution?module=neutron-group&project_type=openstack&days=90>`_
* `180 day review stats <https://www.stackalytics.io/report/contribution?module=neutron-group&project_type=openstack&days=180>`_
