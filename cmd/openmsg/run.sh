#!/bin/sh

export ENV_SECRET_KEY_LOCATION=../sealmsg/sample.d/.secret/key1time.secret.dat
export ENV_CIPHER_TXT_LOCATION=../sealmsg/sample.d/msg.sealed.txt

./openmsg
