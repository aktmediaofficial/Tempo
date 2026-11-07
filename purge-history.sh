#!/usr/bin/env bash
# Removes the leaked song MP3 and the upload zips from the ENTIRE git history of aktmedia.
# Run this on a FRESH clone (git-filter-repo refuses to run on a clone that has work in progress).
# Needs: git, Python 3, and `pip install git-filter-repo`
#
# Do this BEFORE applying aktmedia-security.patch (the patch applies fine to the cleaned repo).
# Afterwards every commit hash changes, so anyone else with a copy must re-clone.
set -euo pipefail

REPO_URL="https://github.com/aktmediaofficial/aktmedia.git"   # use SSH or a token URL if the repo is private
WORKDIR="aktmedia-clean"

git clone "$REPO_URL" "$WORKDIR"
cd "$WORKDIR"

git filter-repo --invert-paths \
  --path 'artifacts/akt-media/public/samples/Ekseni(4).mp3' \
  --path 'aktmedia-changes (1).zip' \
  --path 'aktmedia-changes-only (1).zip' \
  --path 'aktmedia-changes-only.zip'

# filter-repo removes the remote on purpose; add it back and overwrite every branch and tag.
git remote add origin "$REPO_URL"
git push --force --all
git push --force --tags

echo
echo "Done. Confirm it worked (should print nothing):"
echo "  git log --all --name-only --pretty=format: | grep -Ei '\\.(mp3|zip)\$'"
