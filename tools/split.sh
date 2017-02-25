#!/bin/sh
#
# This script has been shamelessly copied and tweaked from original copy:
#
# https://github.com/openstack/oslo-incubator/blob/master/tools/graduate.sh
#
# Use this script to export a Neutron module to a separate git repo.
#
# You can call this script Call script like so:
#
#     ./split.sh <path to file containing list of files to export> <project name>
#
# The file should be a text file like the one below:
#
#  /path/to/file/file1
#  /path/to/file/file2
#  ...
#  /path/to/file/fileN
#
# Such a list can be generated with a command like this:
#
# find $path -type f  # path is the base dir you want to list files for

set -e

if [ $# -lt 2 ]; then
    echo "Usage $0 <path to file containing list of files to export> <project name>"
    exit 1
fi

set -x

file_list_path="$1"
project_name="$2"
files_to_keep=$(cat $file_list_path)


# Build the grep pattern for ignoring files that we want to keep
keep_pattern="\($(echo $files_to_keep | sed -e 's/^/\^/' -e 's/ /\\|\^/g')\)"
# Prune all other files in every commit
pruner="git ls-files | grep -v \"$keep_pattern\" | git update-index --force-remove --stdin; git ls-files > /dev/stderr"

# Find all first commits with listed files and find a subset of them that
# predates all others

roots=""
for file in $files_to_keep; do
    file_root=$(git rev-list --reverse HEAD -- $file | head -n1)
    fail=0
    for root in $roots; do
        if git merge-base --is-ancestor $root $file_root; then
            fail=1
            break
        elif !git merge-base --is-ancestor $file_root $root; then
            new_roots="$new_roots $root"
        fi
    done
    if [ $fail -ne 1 ]; then
        roots="$new_roots $file_root"
    fi
done

# Purge all parents for those commits

set_roots="
if [ 1 -eq 0 $(for root in $roots; do echo " -o \"\$GIT_COMMIT\" = '$root' "; done) ]; then
    echo '';
else
    cat;
fi"

# Enhance git_commit_non_empty_tree to skip merges with:
# a) either two equal parents (commit that was about to land got purged as well
# as all commits on mainline);
# b) or with second parent being an ancestor to the first one (just as with a)
# but when there are some commits on mainline).
# In both cases drop second parent and let git_commit_non_empty_tree to decide
# if commit worth doing (most likely not).

skip_empty=$(cat << \EOF
if [ $# = 5 ] && git merge-base --is-ancestor $5 $3; then
    git_commit_non_empty_tree $1 -p $3
else
    git_commit_non_empty_tree "$@"
fi
EOF
)

# Filter out commits for unrelated files
echo "Pruning commits for unrelated files..."
git filter-branch \
    --index-filter "$pruner" \
    --parent-filter "$set_roots" \
    --commit-filter "$skip_empty" \
    --tag-name-filter cat \
    -- --all

# Generate the new .gitreview file
echo "Generating new .gitreview file..."
cat > .gitreview <<EOF
[gerrit]
host=review.openstack.org
port=29418
project=stackforge/${project_name}.git
EOF

git add . && git commit -m "Generated new .gitreview file for ${project_name}"

echo "Done."
