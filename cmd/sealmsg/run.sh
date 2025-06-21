#!/bin/sh

export ENV_SECRET_KEY_LOCATION=./sample.d/.secret/key1time.secret.dat

mkdir -p ./sample.d/.secret

test -f "${ENV_SECRET_KEY_LOCATION}" || \
	dd \
		if=/dev/urandom \
		of="${ENV_SECRET_KEY_LOCATION}" \
		bs=32 \
		count=1 \
		conv=fsync \
		status=progress

export ENV_PLAIN_TXT_LOCATION=./sample.d/msg.plain.txt

echo 'hello,world' > "${ENV_PLAIN_TXT_LOCATION}"

sealed=./sample.d/msg.sealed.txt

./sealmsg |
	dd \
		if=/dev/stdin \
		of="${sealed}" \
		bs=1048576 \
		status=none

ls -l \
	"${ENV_PLAIN_TXT_LOCATION}" \
	"${sealed}"

xxd "${ENV_PLAIN_TXT_LOCATION}"
xxd "${sealed}"
