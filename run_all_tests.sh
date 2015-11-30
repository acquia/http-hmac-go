#!/bin/bash

cdir="$1"
if [ -z "$cdir" ]; then
	cdir="."
fi

for fn in "$cdir"/*; do
	if [ -d "$fn" ]; then
		$0 "$fn"
	fi
done
if [ -n "$(find "$cdir" -maxdepth 1 -name '*_test.go' -print -quit)" ]; then
	echo "$cdir: $(shopt -s nullglob; echo "$cdir/"*_test.go)"
	cd $cdir
	go test -v -cover
	cd - >/dev/null
	exit 0
fi

exit 0