#!/usr/bin/env bash
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# WARNING!
# Please do not run this script without talking to the Neutron PTL. Auto
# abandoning people's changes is a good thing, but must be done with care.
#
# before you run this modify your .ssh/config to create a
# review.opendev.org entry:
#
#   Host review.opendev.org
#   User <yourgerritusername>
#   Port 29418
#

# Note: due to gerrit bug somewhere, this double posts messages. :(

# first purge all the reviews that are more than 4w old and blocked by a core -2

DRY_RUN=0
CLEAN_PROJECT=""

function print_help {
    echo "Script to abandon patches without activity for more than 4 weeks."
    echo "Usage:"
    echo "      ./abandon_old_reviews.sh [--dry-run] [--project <project_name>] [--help]"
    echo " --dry-run                    In dry-run mode it will only print what patches would be abandoned "
    echo "                              but will not take any real actions in gerrit"
    echo " --project <project_name>     Only check patches from <project_name> if passed."
    echo "                              It must be one of the projects which are a part of the Neutron stadium."
    echo "                              If project is not provided, all projects from the Neutron stadium will be checked"
    echo " --help                       Print help message"
}

while [ $# -gt 0 ]; do
    key="${1}"

    case $key in
        --dry-run)
            echo "Enabling dry run mode"
            DRY_RUN=1
            shift # past argument
        ;;
        --project)
            CLEAN_PROJECT="project:openstack/${2}"
            shift # past argument
            shift # past value
        ;;
        --help)
            print_help
            exit 2
    esac
done

set -o errexit
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function abandon_review {
    local gitid=$1
    shift
    local msg=$@
    # echo ssh review.opendev.org gerrit review $gitid --abandon --message \"$msg\"
    unassign_and_new_bug $gitid
    if [ $DRY_RUN -eq 1 ]; then
        echo "Would abandon $gitid"
    else
        echo "Abandoning $gitid"
        ssh review.opendev.org gerrit review $gitid --abandon --message \"$msg\"
    fi
}

function unassign_and_new_bug {
    # unassign current assignee and set bug to 'new' status
    local gitid=$1
    cm=$(ssh review.opendev.org "gerrit query $gitid --current-patch-set --format json" | jq .commitMessage)
    for closes in $(echo -e $cm | grep -i "closes" | grep -i "bug" | grep -o -E '[0-9]+'); do
        if [ $DRY_RUN -eq 1 ]; then
            echo "Would unassign and tag 'timeout-abandon' $closes"
        else
            echo "Attempting to change status of bug $closes to New"
            python "$DIR/unassign_bug.py" $closes
        fi
    done
}

PROJECTS="($(
python - <<EOF
from urllib.request import urlopen
import yaml

project = "$CLEAN_PROJECT"
data = urlopen("https://raw.githubusercontent.com/openstack/"
                       "governance/master/reference/projects.yaml")
governance = yaml.safe_load(data)
stadium = governance["neutron"]["deliverables"].keys()
query = ["project:openstack/%s" % p for p in stadium]
if project:
    print(project if project in query else "")
else:
    print( ' OR '.join(query))
EOF
))"

if [ "$PROJECTS" = "()" ]; then
    echo "Project $CLEAN_PROJECT not found. It is probably not part of the Neutron deliverables."
    exit 1
fi

blocked_reviews=$(ssh review.opendev.org "gerrit query --current-patch-set --format json $PROJECTS status:open age:4w label:Code-Review<=-2" | jq .currentPatchSet.revision | grep -v null | sed 's/"//g')

blocked_msg=$(cat <<EOF

This review is > 4 weeks without comment and currently blocked by a
core reviewer with a -2. We are abandoning this for now.

Feel free to reactivate the review by pressing the restore button and
contacting the reviewer with the -2 on this review to ensure you
address their concerns.

EOF
)

# For testing, put in a git rev of something you own and uncomment
# blocked_reviews="b6c4218ae4d75b86c33fa3d37c27bc23b46b6f0f"

for review in $blocked_reviews; do
    # echo ssh review.opendev.org gerrit review $review --abandon --message \"$msg\"
    echo "Blocked review $review"
    abandon_review $review $blocked_msg
done

# then purge all the reviews that are > 4w with no changes and Zuul has -1ed

failing_reviews=$(ssh review.opendev.org "gerrit query  --current-patch-set --format json $PROJECTS status:open age:4w NOT label:Verified>=1,Zuul" | jq .currentPatchSet.revision | grep -v null | sed 's/"//g')

failing_msg=$(cat <<EOF

This review is > 4 weeks without comment, and failed Zuul jobs the last
time it was checked. We are abandoning this for now.

Feel free to reactivate the review by pressing the restore button and
leaving a 'recheck' comment to get fresh test results.

EOF
)

for review in $failing_reviews; do
    echo "Failing review $review"
    abandon_review $review $failing_msg
done
