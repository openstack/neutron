Neutron Code Reviews
====================

Code reviews are a critical component of all OpenStack projects. Neutron accepts patches from many
diverse people with diverse backgrounds, employers, and experience levels. Code reviews provide a
way to enforce a level of consistency across the project, and also allow for the careful on boarding
of contributions from new contributors.

Neutron Code Review Practices
-----------------------------
Neutron follows the `code review guidelines <https://wiki.openstack.org/wiki/ReviewChecklist>`_ as
set forth for all OpenStack projects. It is expected that all reviewers are following the guidelines
set forth on that page.

Neutron Spec Review Practices
-----------------------------
In addition to code reviews, Neutron also maintains a BP specification git repository. Detailed
instructions for the use of this repository are provided `here <https://wiki.openstack.org/wiki/Blueprints>`_.
It is expected that Neutron core team members are actively reviewing specifications which are pushed out
for review to the specification repository. In addition, there is a neutron-drivers team, composed of a
handful of Neutron core reviewers, who can approve and merge Neutron specs.

Some guidelines around this process are provided below:

* Once a specification has been pushed, it is expected that it will not be approved for at least 3 days
  after a first Neutron core reviewer has reviewed it. This allows for additional cores to review the
  specification.
* For blueprints which the core team deems of High or Critical importance, core reviewers may be assigned
  based on their subject matter expertise.
* Specification priority will be set by the PTL with review by the core team once the specification is
  approved.

Tracking Review Statistics
--------------------------
Stackalytics provides some nice interfaces to track review statistics. The links are provided below. These
statistics are used to track not only Neutron core reviewer statistics, but also to track review statistics
for potential future core members.

* `30 day review stats <http://stackalytics.com/report/contribution/neutron-group/30>`_
* `60 day review stats <http://stackalytics.com/report/contribution/neutron-group/60>`_
* `90 day review stats <http://stackalytics.com/report/contribution/neutron-group/90>`_
* `180 day review stats <http://stackalytics.com/report/contribution/neutron-group/180>`_
