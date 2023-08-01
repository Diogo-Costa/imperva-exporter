#!/bin/bash

# Function to display error message and exit with a non-zero status
function error_exit {
    echo "Error: $1"
    exit 1
}

# Fetch tags
git fetch --tags

# Get latest tag
GIT_HASH=$(git show --pretty=format:"%h" --no-patch)
# Debug
echo "Git Hash: $GIT_HASH"
# Get Last Tag
TAG=$(git tag |grep "v*" |sort -V |tail -n 1)
# Debug
echo "Last Version: $TAG"

# Remove prefix from semantic version field
VERSION=`echo ${TAG} |awk -F-v '{print \$2}'`
LAST_TAG=$TAG

# if there are none, start tags at v0.0.0
if [ -z "$TAG" ]
then
    echo "No tags found, creating the first"
    LOG=$(git log --pretty=oneline)
    LAST_TAG="v0.0.0"
    MESSAGE="Initial tag v0.0.0"
    git config user.name "Diogo-Costa"
    git config user.email "Diogo-Costa@users.noreply.github.com"
    git tag -a "${LAST_TAG}" -m "${MESSAGE}"
    git push origin "${LAST_TAG}"
    VERSION=v0.0.0
else
    LOG=$(git log "$TAG..HEAD" --pretty=oneline |head -n 1)
    echo "Last commit: $LOG"
fi

# Make increment version based on the last log commit
case "$LOG" in
    *#major* ) 
        echo "Major increment"
        VERSION=$(echo $VERSION |awk -F. '{ print $1+1 FS 0 FS 0 }');;
    *#minor* ) 
        echo "Minor increment"
        VERSION=$(echo $VERSION |awk -F. '{ print $1 FS $2+1 FS 0 }');;
    *#patch* ) 
        echo "Patch increment"
        VERSION=$(echo $VERSION |awk -F. '{ print $1 FS $2 FS $3+1 }');;
    * )
        echo "ERROR: increment version dont defined"
        exit 1
esac

# Push new tag
NEW_TAG="v$VERSION"
# Debug
echo "New VERSION: v$VERSION"
MESSAGE="New TAG v$VERSION"
git config user.name "Diogo-Costa"
git config user.email "Diogo-Costa@users.noreply.github.com"
git tag -a "${NEW_TAG}" -m "${MESSAGE}" || error_exit "Failed to create the tag"
git push origin "${NEW_TAG}" || error_exit "Failed to push the tag"

# Update tags
git fetch --tags

# Set outputs for used in Github Actions
echo "new_tag=$NEW_TAG" >> $GITHUB_OUTPUT
