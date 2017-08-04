===========================
Neutron Release Notes Howto
===========================

Release notes are a new feature for documenting new features in
OpenStack projects. Background on the process, tooling, and
methodology is documented in a `mailing list post by Doug Hellmann <http://lists.openstack.org/pipermail/openstack-dev/2015-November/078301.html>`_.

Writing release notes
---------------------

For information on how to create release notes, please consult the
`reno documentation <https://docs.openstack.org/reno/latest/user/usage.html>`__.

Please keep the following in your mind when you write release notes.

* **Avoid using "prelude" section** for individual release notes.
  "prelude" section is for general comments about the release.
* **Use one entry per section** (like "feature" or "upgrade").
  All entries which belong to a same release will be merged and rendered,
  so there is less meaning to use multiple entries by a single topic.

Maintaining release notes
-------------------------

.. warning::

   Avoid modifying an existing release note file even though it is related
   to your change. If you modify a release note file of a past release,
   the whole content will be shown in a latest release. The only allowed
   case is to update a release note in a same release.

   If you need to update a release note of a past release,
   edit a corresponding release note file in a stable branch directly.
