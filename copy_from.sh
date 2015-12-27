#!/bin/sh
curl https://copy.suehiro.ne.jp/index.php -X POST --form-string "user_name=$1" --form-string "access_key=$2"
