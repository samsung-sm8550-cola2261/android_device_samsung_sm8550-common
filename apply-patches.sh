#!/bin/bash

PATCHES="device/samsung/sm8550-common/patches"

# Find AOSP root
TOP="$PWD"
while [ "$TOP" != "/" ] && [ ! -d "$TOP/.repo" ]; do
    TOP="$(dirname "$TOP")"
done

[ -d "$TOP/.repo" ] || {
    echo "error: Not inside an AOSP source tree!"
    exit 1
}

find "$TOP/$PATCHES" -name '*.patch' -print0 | sort -z | while IFS= read -r -d '' PATCH; do
    REPO=$(dirname "${PATCH#$TOP/$PATCHES/}")

    echo "Checking $PATCH ..."
    (
        cd "$TOP/$REPO" || exit 1

        if git apply --check "$PATCH"; then
            git apply "$PATCH"
            echo "Applied: $(basename "$PATCH")"
        elif git apply --reverse --check "$PATCH"; then
            echo "Already applied: $(basename "$PATCH")"
        else
            echo "Failed to apply: $(basename "$PATCH")"
        fi
    )
done

echo "Done"
