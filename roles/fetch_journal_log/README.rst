Collect journal log from test run

By default, this stores journal log into log file and store it in
"journal_log_file_path"

**Role Variables**

.. zuul:rolevar:: journal_log_path
   :default: {{ ansible_user_dir }}/workspace/logs

   Path where journal log file will be stored on job's node.

.. zuul:rolevar:: journal_log_file_name
   :default: {{ journal_log_path }}/journal.log

   Name of journal log file.
