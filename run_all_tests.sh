#!/bin/bash

cdir="$1"
if [ -z "$cdir" ]; then
	cdir="."
fi

ec=0
for fn in "$cdir"/*; do
	if [ -d "$fn" ]; then
		if basename $cdir | grep -E '(http-hmac-go|_vendor)'; then
			continue
		fi
		$0 "$fn"
		ed=$?
		if [ $ec -eq 0 ]; then
			ec=$ed
		fi
	fi
done

if [ -n "$(find "$cdir" -maxdepth 1 -name '*_test.go' -print -quit)" ]; then
	echo "$cdir: $(find "$cdir" -maxdepth 1 -name '*_test.go' -print -quit)"
	cd $cdir
	go test -v -cover
	ed=$?
	if [ $ec -eq 0 ]; then
		ec=$ed
	fi
	cd - >/dev/null
	exit $ec
fi

exit $ec
