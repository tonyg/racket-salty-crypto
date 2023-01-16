#!/bin/sh
#
# Set up a git checkout of this repository for local dev use.

exec 2>/dev/tty 1>&2

set -e

[ -d .git ] || exit 0

for fullhook in ./git-hooks/*
do
    hook=$(basename "$fullhook")
    [ -L .git/hooks/$hook ] || (
        echo "Installing $hook hook"
        ln -s ../../git-hooks/$hook .git/hooks/$hook
    )
done
