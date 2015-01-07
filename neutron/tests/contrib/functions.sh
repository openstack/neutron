#!/bin/bash

# Copyright (C) 2011-2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.

# Distro check functions
function is_fedora {
    # note we consider CentOS 7 as fedora for now
    lsb_release -i 2>/dev/null | grep -iq "fedora" || \
        lsb_release -i 2>/dev/null | grep -iq "CentOS"
}

function is_ubuntu {
    lsb_release -i 2>/dev/null | grep -iq "ubuntu"
}

function is_debian {
    # do not rely on lsb_release because it may be not installed by default
    cat /etc/*-release | grep ID 2>/dev/null | grep -iq "debian"
}

function uses_debs {
    # check if apt-get is installed, valid for debian based
    type "apt-get" 2>/dev/null
}

function function_exists {
    type $1 2>/dev/null | grep -q 'is a function'
}

# awk filter to timestamp the stream, including stderr merging
function tsfilter {
    $@ 2>&1 | awk '
    {
        cmd ="date +\"%Y-%m-%d %H:%M:%S.%3N | \""
        cmd | getline now
        close("date +\"%Y-%m-%d %H:%M:%S.%3N | \"")
        sub(/^/, now)
        print
        fflush()
    }'
}

function _ping_check {
    local host=$1
    local times=${2:-20}
    echo "Testing ICMP connectivit to $host"
    ping -c $times $host
}

function _http_check {
    local url=$1
    local dl='wget --progress=bar -O /dev/null'
    if [[ `which curl` ]]; then
        dl='curl -# -o /dev/null'
    fi

    # do a pypi http fetch, to make sure that we're good
    for i in `seq 1 10`; do
        echo "HTTP check of $url - attempt #$i"
        $dl $url || /bin/true
    done
}

# do a few network tests to baseline how bad we are
function network_sanity_check {
    echo "Performing network sanity check..."
    PIP_CONFIG_FILE=$HOME/.pip/pip.conf
    if [[ -f $PIP_CONFIG_FILE ]]; then
        line=$(cat $PIP_CONFIG_FILE|grep index-url)
        pypi_url=${line#*=}
        pypi_host=$(echo $pypi_url|grep -Po '.*?//\K.*?(?=/)')

        _ping_check $pypi_host
        _http_check $pypi_url
    fi

    # rax ubuntu mirror
    _ping_check mirror.rackspace.com
    _http_check http://mirror.rackspace.com/ubuntu/dists/trusty/Release.gpg
}

# create the start timer for when the job began
function start_timer {
    # first make sure the time is right, so we don't go into crazy land
    # later if the system decides to apply an ntp date and we jump forward
    # 4 hrs (which has happened)
    if is_fedora; then
        local ntp_service='ntpd'
    elif uses_debs; then
        local ntp_service='ntp'
    else
        echo "Unsupported platform, can't determine ntp service"
        exit 1
    fi
    local default_ntp_server=$(
        grep ^server /etc/ntp.conf | head -1 | awk '{print $2}')
    local ntp_server=${NTP_SERVER:-$default_ntp_server}
    sudo service $ntp_service stop
    sudo /usr/sbin/ntpdate $ntp_server
    sudo service $ntp_service start
    sleep 1
    START_TIME=`date +%s`
}

function remaining_time {
    local now=`date +%s`
    local elapsed=$(((now - START_TIME) / 60))
    REMAINING_TIME=$((DEVSTACK_GATE_TIMEOUT - elapsed - 5))
    echo "Job timeout set to: $REMAINING_TIME minutes"
}

# indent the output of a command 4 spaces, useful for distinguishing
# the output of a command from the command itself
function indent {
    $@ | (while read; do echo "    $REPLY"; done)
}

# Attempt to fetch a git ref for a project, if that ref is not empty
function git_fetch_at_ref {
    local project=$1
    local ref=$2
    if [ "$ref" != "" ]; then
        git fetch $ZUUL_URL/$project $ref
        return $?
    else
        # return failing
        return 1
    fi
}

function git_checkout {
    local project=$1
    local branch=$2
    local reset_branch=$branch

    if [[ "$branch" != "FETCH_HEAD" ]]; then
        reset_branch="remotes/origin/$branch"
    fi

    git checkout $branch
    git reset --hard $reset_branch
    if ! git clean -x -f -d -q ; then
        sleep 1
        git clean -x -f -d -q
    fi
}

function git_has_branch {
    local project=$1 # Project is here for test mocks
    local branch=$2

    if git branch -a |grep remotes/origin/$branch>/dev/null; then
        return 0
    else
        return 1
    fi
}

function git_prune {
    git remote prune origin
}

function git_remote_update {
    # Attempt a git remote update. Run for up to 5 minutes before killing.
    # If first SIGTERM does not kill the process wait a minute then SIGKILL.
    # If update fails try again for up to a total of 3 attempts.
    MAX_ATTEMPTS=3
    COUNT=0
    until timeout -k 1m 5m git remote update; do
        COUNT=$(($COUNT + 1))
        echo "git remote update failed."
        if [ $COUNT -eq $MAX_ATTEMPTS ]; then
            echo "Max attempts reached for git remote update; giving up."
            exit 1
        fi
        SLEEP_TIME=$((30 + $RANDOM % 60))
        echo "sleep $SLEEP_TIME before retrying."
        sleep $SLEEP_TIME
    done
}

function git_remote_set_url {
    git remote set-url $1 $2
}

function git_clone_and_cd {
    local project=$1
    local short_project=$2
    local git_base=${GIT_BASE:-https://git.openstack.org}

    if [[ ! -e $short_project ]]; then
        echo "  Need to clone $short_project"
        git clone $git_base/$project
    fi
    cd $short_project
}

function fix_etc_hosts {
    # HPcloud stopped adding the hostname to /etc/hosts with their
    # precise images.

    HOSTNAME=`/bin/hostname`
    if ! grep $HOSTNAME /etc/hosts >/dev/null; then
        echo "Need to add hostname to /etc/hosts"
        sudo bash -c 'echo "127.0.1.1 $HOSTNAME" >>/etc/hosts'
    fi

}

function fix_disk_layout {
    # HPCloud and Rackspace performance nodes provide no swap, but do
    # have ephemeral disks we can use.  HPCloud also doesn't have
    # enough space on / for two devstack installs, so we partition the
    # disk and mount it on /opt, syncing the previous contents of /opt
    # over.
    if [ `grep SwapTotal /proc/meminfo | awk '{ print $2; }'` -eq 0 ]; then
        if [ -b /dev/vdb ]; then
            DEV='/dev/vdb'
        elif [ -b /dev/xvde ]; then
            DEV='/dev/xvde'
        fi
        if [ -n "$DEV" ]; then
            local swap=${DEV}1
            local lvmvol=${DEV}2
            local optdev=${DEV}3
            sudo umount ${DEV}
            sudo parted ${DEV} --script -- mklabel msdos
            sudo parted ${DEV} --script -- mkpart primary linux-swap 1 8192
            sudo parted ${DEV} --script -- mkpart primary ext2 8192 32768
            sudo parted ${DEV} --script -- mkpart primary ext2 32768 -1
            sudo mkswap $swap
            sudo vgcreate stack-volumes-lvmdriver-1 $lvmvol
            sudo mkfs.ext4 $optdev
            sudo swapon $swap
            sudo mount $optdev /mnt
            sudo find /opt/ -mindepth 1 -maxdepth 1 -exec mv {} /mnt/ \;
            sudo umount /mnt
            sudo mount $optdev /opt
        fi
    fi
}

# Set up a project in accordance with the future state proposed by
# Zuul.
#
# Arguments:
#   project: The full name of the project to set up
#   branch: The branch to check out
#
# The branch argument should be the desired branch to check out.  If
# you have no other opinions, then you should supply ZUUL_BRANCH here.
# This is generally the branch corresponding with the change being
# tested.
#
# If you would like to check out a branch other than what ZUUL has
# selected, for example in order to check out the old or new branches
# for grenade, or an alternate branch to test client library
# compatibility, then supply that as the argument instead.  This
# function will try to check out the following (in order):
#
#   The zuul ref for the project specific OVERRIDE_$PROJECT_PROJECT_BRANCH if specified
#   The zuul ref for the indicated branch
#   The zuul ref for the master branch
#   The tip of the project specific OVERRIDE_$PROJECT_PROJECT_BRANCH if specified
#   The tip of the indicated branch
#   The tip of the master branch
#
function setup_project {
    local project=$1
    local branch=$2
    local short_project=`basename $project`
    local git_base=${GIT_BASE:-https://git.openstack.org}

    echo "Setting up $project @ $branch"
    git_clone_and_cd $project $short_project

    git_remote_set_url origin $git_base/$project

    # allow for possible project branch override
    local uc_project=`echo $short_project | tr [:lower:] [:upper:] | tr '-' '_' | sed 's/[^A-Z_]//'`
    local project_branch_var="\$OVERRIDE_${uc_project}_PROJECT_BRANCH"
    local project_branch=`eval echo ${project_branch_var}`
    if [[ "$project_branch" != "" ]]; then
        branch=$project_branch
    fi

    # Try the specified branch before the ZUUL_BRANCH.
    OVERRIDE_ZUUL_REF=$(echo $ZUUL_REF | sed -e "s,$ZUUL_BRANCH,$branch,")

    # Update git remotes
    git_remote_update
    # Ensure that we don't have stale remotes around
    git_prune
    # See if this project has this branch, if not, use master
    FALLBACK_ZUUL_REF=""
    if ! git_has_branch $project $branch; then
        FALLBACK_ZUUL_REF=$(echo $ZUUL_REF | sed -e "s,$branch,master,")
    fi

    # See if Zuul prepared a ref for this project
    if git_fetch_at_ref $project $OVERRIDE_ZUUL_REF || \
        git_fetch_at_ref $project $FALLBACK_ZUUL_REF; then

        # It's there, so check it out.
        git_checkout $project FETCH_HEAD
    else
        if git_has_branch $project $branch; then
            git_checkout $project $branch
        else
            git_checkout $project master
        fi
    fi
}

function re_exec_devstack_gate {
    export RE_EXEC="true"
    echo "This build includes a change to devstack-gate; re-execing this script."
    exec $WORKSPACE/devstack-gate/devstack-vm-gate-wrap.sh
}

function setup_workspace {
    local base_branch=$1
    local DEST=$2
    local copy_cache=$3
    local xtrace=$(set +o | grep xtrace)

    # Enabled detailed logging, since output of this function is redirected
    set -o xtrace

    fix_disk_layout

    sudo mkdir -p $DEST
    sudo chown -R jenkins:jenkins $DEST

    #TODO(jeblair): remove when this is no longer created by the image
    rm -fr ~/workspace-cache/

    # The vm template update job should cache the git repos
    # Move them to where we expect:
    echo "Using branch: $base_branch"
    for PROJECT in $PROJECTS; do
        cd $DEST
        if [ -d /opt/git/$PROJECT ]; then
            # Start with a cached git repo if possible
            rsync -a /opt/git/${PROJECT}/ `basename $PROJECT`
        fi
        setup_project $PROJECT $base_branch
    done
    # It's important we are back at DEST for the rest of the script
    cd $DEST

    if [ -n "$copy_cache" ] ; then
        # The vm template update job should cache some images in ~/cache.
        # Move them to where devstack expects:
        find ~/cache/files/ -mindepth 1 -maxdepth 1 -exec cp {} $DEST/devstack/files/ \;
    else
        # The vm template update job should cache some images in ~/cache.
        # Move them to where devstack expects:
        find ~/cache/files/ -mindepth 1 -maxdepth 1 -exec mv {} $DEST/devstack/files/ \;
    fi

    # Disable detailed logging as we return to the main script
    $xtrace
}

function copy_mirror_config {

    sudo install -D -m0644 -o root -g root ~/.pydistutils.cfg ~root/.pydistutils.cfg
    sudo install -D -m0644 -o root -g root ~/.pip/pip.conf ~root/.pip/pip.conf

    sudo install -D -m0644 -o stack -g stack ~/.pydistutils.cfg ~stack/.pydistutils.cfg
    sudo install -D -m0644 -o stack -g stack ~/.pip/pip.conf ~stack/.pip/pip.conf

    sudo install -D -m0644 -o tempest -g tempest ~/.pydistutils.cfg ~tempest/.pydistutils.cfg
    sudo install -D -m0644 -o tempest -g tempest ~/.pip/pip.conf ~tempest/.pip/pip.conf

}

function setup_host {
    # Enabled detailed logging, since output of this function is redirected
    local xtrace=$(set +o | grep xtrace)
    set -o xtrace

    echo "What's our kernel?"
    uname -a

    # capture # of cpus
    echo "NProc has discovered $(nproc) CPUs"
    cat /proc/cpuinfo

    # This is necessary to keep sudo from complaining
    fix_etc_hosts

    # Move the PIP cache into position:
    sudo mkdir -p /var/cache/pip
    sudo mv ~/cache/pip/* /var/cache/pip

    # We set some home directories under $BASE, make sure it exists.
    sudo mkdir -p $BASE

    # Start with a fresh syslog
    if uses_debs; then
        sudo stop rsyslog
        sudo mv /var/log/syslog /var/log/syslog-pre-devstack
        sudo mv /var/log/kern.log /var/log/kern_log-pre-devstack
        sudo touch /var/log/syslog
        sudo chown /var/log/syslog --ref /var/log/syslog-pre-devstack
        sudo chmod /var/log/syslog --ref /var/log/syslog-pre-devstack
        sudo chmod a+r /var/log/syslog
        sudo touch /var/log/kern.log
        sudo chown /var/log/kern.log --ref /var/log/kern_log-pre-devstack
        sudo chmod /var/log/kern.log --ref /var/log/kern_log-pre-devstack
        sudo chmod a+r /var/log/kern.log
        sudo start rsyslog
    elif is_fedora; then
        # save timestamp and use journalctl to dump everything since
        # then at the end
        date +"%Y-%m-%d %H:%M:%S" | sudo tee $BASE/log-start-timestamp.txt
    fi

    # Create a stack user for devstack to run as, so that we can
    # revoke sudo permissions from that user when appropriate.
    sudo useradd -U -s /bin/bash -d $BASE/new -m stack
    # Use 755 mode on the user dir regarless to the /etc/login.defs setting
    sudo chmod 755 $BASE/new
    TEMPFILE=`mktemp`
    echo "stack ALL=(root) NOPASSWD:ALL" >$TEMPFILE
    chmod 0440 $TEMPFILE
    sudo chown root:root $TEMPFILE
    sudo mv $TEMPFILE /etc/sudoers.d/50_stack_sh

    # Create user's ~/.cache directory with proper permissions, ensuring later
    # 'sudo pip install's do not create it owned by root.
    sudo mkdir -p $BASE/new/.cache
    sudo chown -R stack:stack $BASE/new/.cache

    # Create a tempest user for tempest to run as, so that we can
    # revoke sudo permissions from that user when appropriate.
    # NOTE(sdague): we should try to get the state dump to be a
    # neutron API call in Icehouse to remove this.
    sudo useradd -U -s /bin/bash -m tempest
    TEMPFILE=`mktemp`
    echo "tempest ALL=(root) NOPASSWD:/sbin/ip" >$TEMPFILE
    echo "tempest ALL=(root) NOPASSWD:/sbin/iptables" >>$TEMPFILE
    echo "tempest ALL=(root) NOPASSWD:/usr/bin/ovsdb-client" >>$TEMPFILE
    chmod 0440 $TEMPFILE
    sudo chown root:root $TEMPFILE
    sudo mv $TEMPFILE /etc/sudoers.d/51_tempest_sh

    # Future useradd calls should strongly consider also updating
    # ~/.pip/pip.conf and ~/.pydisutils.cfg in the copy_mirror_config
    # function if tox/pip will be used at all.

    # If we will be testing OpenVZ, make sure stack is a member of the vz group
    if [ "$DEVSTACK_GATE_VIRT_DRIVER" == "openvz" ]; then
        sudo usermod -a -G vz stack
    fi

    # Ensure that all of the users have the openstack mirror config
    copy_mirror_config

    # perform network sanity check so that we can characterize the
    # state of the world
    network_sanity_check

    # Disable detailed logging as we return to the main script
    $xtrace
}

function cleanup_host {
    # Enabled detailed logging, since output of this function is redirected
    local xtrace=$(set +o | grep xtrace)
    set -o xtrace

    cd $WORKSPACE

    # Sleep to give services a chance to flush their log buffers.
    sleep 2

    # No matter what, archive logs and config files
    if uses_debs; then
        sudo cp /var/log/syslog $BASE/logs/syslog.txt
        sudo cp /var/log/kern.log $BASE/logs/kern_log.txt
    elif is_fedora; then
        # the journal gives us syslog() and kernel output, so is like
        # a concatenation of the above.
        sudo journalctl --no-pager \
            --since="$(cat $BASE/log-start-timestamp.txt)" \
            | sudo tee $BASE/logs/syslog.txt > /dev/null
    fi

    # apache logs; including wsgi stuff like horizon, keystone, etc.
    if uses_debs; then
        local apache_logs=/var/log/apache2
    elif is_fedora; then
        local apache_logs=/var/log/httpd
    fi
    sudo cp -r ${apache_logs} $BASE/logs/apache

    # rabbitmq logs
    if [ -d /var/log/rabbitmq ]; then
        sudo cp -r /var/log/rabbitmq $BASE/logs
    fi

    # db logs
    if [ -d /var/log/postgresql ] ; then
        # Rename log so it doesn't have an additional '.' so it won't get
        # deleted
        sudo cp /var/log/postgresql/*log $BASE/logs/postgres.log
    fi
    if [ -f /var/log/mysql.err ] ; then
        sudo cp /var/log/mysql.err $BASE/logs/mysql_err.log
    fi
    if [ -f /var/log/mysql.log ] ; then
        sudo cp /var/log/mysql.log $BASE/logs/
    fi

    # libvirt
    if [ -d /var/log/libvirt ] ; then
        sudo cp -r /var/log/libvirt $BASE/logs/
    fi

    # sudo config
    sudo cp -r /etc/sudoers.d $BASE/logs/
    sudo cp /etc/sudoers $BASE/logs/sudoers.txt

    # Archive config files
    sudo mkdir $BASE/logs/etc/
    for PROJECT in $PROJECTS; do
        proj=`basename $PROJECT`
        if [ -d /etc/$proj ]; then
            sudo cp -r /etc/$proj $BASE/logs/etc/
        fi
    done

    # Archive Apache config files
    sudo mkdir $BASE/logs/apache_config
    if uses_debs; then
        if [[ -d /etc/apache2/sites-enabled ]]; then
            sudo cp /etc/apache2/sites-enabled/* $BASE/logs/apache_config
        fi
    elif is_fedora; then
        if [[ -d /etc/apache2/httpd/conf.d ]]; then
            sudo cp /etc/httpd/conf.d/* $BASE/logs/apache_config
        fi
    fi

    # copy devstack log files
    if [ -d $BASE/old ]; then
        sudo mkdir -p $BASE/logs/old $BASE/logs/new

        # copy all log files, but note that devstack creates a shortened
        # symlink without timestamp (foo.log -> foo.2014-01-01-000000.log)
        # for each log to latest log. Thus we just copy the symlinks to
        # avoid excessively long file-names.
        find $BASE/old/screen-logs -type l -print0 | \
            xargs -0 -I {} sudo cp {} $BASE/logs/old
        sudo cp $BASE/old/devstacklog.txt $BASE/logs/old/
        sudo cp $BASE/old/devstack/localrc $BASE/logs/old/localrc.txt
        sudo cp $BASE/old/tempest/etc/tempest.conf $BASE/logs/old/tempest_conf.txt
        if -f [ $BASE/old/devstack/tempest.log ] ; then
            sudo cp $BASE/old/devstack/tempest.log $BASE/logs/old/verify_tempest_conf.log
        fi

        # grenade logs
        sudo cp $BASE/new/grenade/localrc $BASE/logs/grenade_localrc.txt
        # grenade logs directly and uses similar timestampped files to
        # devstack.  So temporarily copy out & rename the latest log
        # files from the short-symlinks into grenade/, clean-up left
        # over time-stampped files and put the interesting logs back at
        # top-level for easy access
        sudo mkdir -p $BASE/logs/grenade
        sudo cp $BASE/logs/grenade.sh.log $BASE/logs/grenade/
        sudo cp $BASE/logs/grenade.sh.log.summary \
            $BASE/logs/grenade/grenade.sh.summary.log
        sudo rm $BASE/logs/grenade.sh.*
        sudo mv $BASE/logs/grenade/*.log $BASE/logs
        sudo rm -rf $BASE/logs/grenade
        if [ -f $BASE/new/grenade/javelin.log ] ; then
            sudo cp $BASE/new/grenade/javelin.log $BASE/logs/javelin.log
        fi

        NEWLOGTARGET=$BASE/logs/new
    else
        NEWLOGTARGET=$BASE/logs
    fi
    find $BASE/new/screen-logs -type l -print0 | \
        xargs -0 -I {} sudo cp {} $NEWLOGTARGET/
    sudo cp $BASE/new/devstacklog.txt $NEWLOGTARGET/
    sudo cp $BASE/new/devstack/localrc $NEWLOGTARGET/localrc.txt
    if [ -f $BASE/new/devstack/tempest.log ]; then
        sudo cp $BASE/new/devstack/tempest.log $NEWLOGTARGET/verify_tempest_conf.log
    fi

    # Copy failure files if they exist
    if [ $(ls $BASE/status/stack/*.failure | wc -l) -gt 0 ]; then
        sudo mkdir -p $BASE/logs/status
        sudo cp $BASE/status/stack/*.failure $BASE/logs/status/
    fi

    # Copy Ironic nodes console logs if they exist
    if [ -d $BASE/new/ironic-bm-logs ] ; then
        sudo mkdir -p $BASE/logs/ironic-bm-logs
        sudo cp $BASE/new/ironic-bm-logs/*.log $BASE/logs/ironic-bm-logs/
    fi

    # Copy tempest config file
    sudo cp $BASE/new/tempest/etc/tempest.conf $NEWLOGTARGET/tempest_conf.txt

    sudo iptables-save > $WORKSPACE/iptables.txt
    df -h > $WORKSPACE/df.txt
    pip freeze > $WORKSPACE/pip-freeze.txt
    sudo mv $WORKSPACE/iptables.txt $WORKSPACE/df.txt \
        $WORKSPACE/pip-freeze.txt $BASE/logs/

    if [ `command -v dpkg` ]; then
        dpkg -l> $WORKSPACE/dpkg-l.txt
        gzip -9 dpkg-l.txt
        sudo mv $WORKSPACE/dpkg-l.txt.gz $BASE/logs/
    fi
    if [ `command -v rpm` ]; then
        rpm -qa > $WORKSPACE/rpm-qa.txt
        gzip -9 rpm-qa.txt
        sudo mv $WORKSPACE/rpm-qa.txt.gz $BASE/logs/
    fi

    # Process testr artifacts.
    if [ -f $BASE/new/tempest/.testrepository/0 ]; then
        pushd $BASE/new/tempest
        sudo testr last --subunit > $WORKSPACE/testrepository.subunit
        popd
        sudo mv $WORKSPACE/testrepository.subunit $BASE/logs/testrepository.subunit
        sudo python /usr/local/jenkins/slave_scripts/subunit2html.py $BASE/logs/testrepository.subunit $BASE/logs/testr_results.html
        sudo gzip -9 $BASE/logs/testrepository.subunit
        sudo gzip -9 $BASE/logs/testr_results.html
        sudo chown jenkins:jenkins $BASE/logs/testrepository.subunit.gz $BASE/logs/testr_results.html.gz
        sudo chmod a+r $BASE/logs/testrepository.subunit.gz $BASE/logs/testr_results.html.gz
    elif [ -f $BASE/new/tempest/.testrepository/tmp* ]; then
        # If testr timed out, collect temp file from testr
        sudo cp $BASE/new/tempest/.testrepository/tmp* $BASE/logs/testrepository.subunit
        sudo gzip -9 $BASE/logs/testrepository.subunit
        sudo chown jenkins:jenkins $BASE/logs/testrepository.subunit.gz
        sudo chmod a+r $BASE/logs/testrepository.subunit.gz
    fi
    if [ -f $BASE/old/tempest/.testrepository/0 ]; then
        pushd $BASE/old/tempest
        sudo testr last --subunit > $WORKSPACE/testrepository.subunit
        popd
        sudo mv $WORKSPACE/testrepository.subunit $BASE/logs/old/testrepository.subunit
        sudo python /usr/local/jenkins/slave_scripts/subunit2html.py $BASE/logs/old/testrepository.subunit $BASE/logs/old/testr_results.html
        sudo gzip -9 $BASE/logs/old/testrepository.subunit
        sudo gzip -9 $BASE/logs/old/testr_results.html
        sudo chown jenkins:jenkins $BASE/logs/old/testrepository.subunit.gz $BASE/logs/old/testr_results.html.gz
        sudo chmod a+r $BASE/logs/old/testrepository.subunit.gz $BASE/logs/old/testr_results.html.gz
    elif [ -f $BASE/old/tempest/.testrepository/tmp* ]; then
        # If testr timed out, collect temp file from testr
        sudo cp $BASE/old/tempest/.testrepository/tmp* $BASE/logs/old/testrepository.subunit
        sudo gzip -9 $BASE/logs/old/testrepository.subunit
        sudo chown jenkins:jenkins $BASE/logs/old/testrepository.subunit.gz
        sudo chmod a+r $BASE/logs/old/testrepository.subunit.gz
    fi

    if [ -f $BASE/new/tempest/tempest.log ] ; then
        sudo cp $BASE/new/tempest/tempest.log $BASE/logs/tempest.log
    fi
    if [ -f $BASE/old/tempest/tempest.log ] ; then
        sudo cp $BASE/old/tempest/tempest.log $BASE/logs/old/tempest.log
    fi

    # Make sure jenkins can read all the logs and configs
    sudo chown -R jenkins:jenkins $BASE/logs/
    sudo chmod a+r $BASE/logs/ $BASE/logs/etc

    # rename files to .txt; this is so that when displayed via
    # logs.openstack.org clicking results in the browser shows the
    # files, rather than trying to send it to another app or make you
    # download it, etc.

    # firstly, rename all .log files to .txt files
    for f in $(find $BASE/logs -name "*.log"); do
        sudo mv $f ${f/.log/.txt}
    done

    #rename all failure files to have .txt
    for f in $(find $BASE/logs/status -name "*.failure"); do
        sudo mv $f ${f/.failure/.txt}
    done

    # append .txt to all config files
    # (there are some /etc/swift .builder and .ring files that get
    # caught up which aren't really text, don't worry about that)
    find $BASE/logs/sudoers.d $BASE/logs/etc -type f -exec mv '{}' '{}'.txt \;

    # rabbitmq
    if [ -f $BASE/logs/rabbitmq/ ]; then
        find $BASE/logs/rabbitmq -type f -exec mv '{}' '{}'.txt \;
        for X in `find $BASE/logs/rabbitmq -type f` ; do
            mv "$X" "${X/@/_at_}"
        done
    fi

    # final memory usage and process list
    ps -eo user,pid,ppid,lwp,%cpu,%mem,size,rss,cmd > $BASE/logs/ps.txt

    # Compress all text logs
    sudo find $BASE/logs -iname '*.txt' -execdir gzip -9 {} \+
    sudo find $BASE/logs -iname '*.dat' -execdir gzip -9 {} \+
    sudo find $BASE/logs -iname '*.conf' -execdir gzip -9 {} \+

    # Disable detailed logging as we return to the main script
    $xtrace
}

function remote_command {
    local ssh_opts="-tt -o PasswordAuthentication=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectionAttempts=4"
    local dest_host=$1
    shift
    ssh $ssh_opts $dest_host "$@"
}

function remote_copy_dir {
    local dest_host=$1
    local src_dir=$2
    local dest_dir=$3
    remote_command "$dest_host"  mkdir -p "$dest_dir"
    rsync -avz "$src_dir" "${dest_host}:$dest_dir"
}

function remote_copy_file {
    local ssh_opts="-o PasswordAuthentication=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectionAttempts=4"
    local src=$1
    local dest=$2
    shift
    scp $ssh_opts "$src" "$dest"
}

# if_name: Interface name on each host
# offset: starting key value for the gre tunnels (MUST not be overlapping)
# host_ip: ip address of the bridge host which is reachable for all peer
# every additinal paramater is considered as a peer host
function gre_bridge {
    local if_name=$1
    local offset=$2
    local host_ip=$3
    shift 3
    local peer_ips=$@
    sudo brctl addbr ${if_name}_br
    sudo iptables -I FORWARD -m physdev --physdev-is-bridged -j ACCEPT
    local key=$offset
    for node in $peer_ips; do
        sudo ip link add gretap_$key type gretap local $host_ip remote $node key $key
        sudo ip link set gretap_$key up
        remote_command $node sudo -i ip link add ${if_name} type gretap local $node remote $host_ip key $key
        remote_command $node sudo -i ip link set ${if_name} up
        sudo brctl addif ${if_name}_br gretap_$key
        (( key++ ))
    done
    sudo ip link add ${if_name}_br_if type veth peer name ${if_name}
    sudo brctl addif ${if_name}_br ${if_name}_br_if
    sudo ip link set ${if_name}_br_if up
    sudo ip link set ${if_name} up
    sudo ip link set ${if_name}_br up
}
