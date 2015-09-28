#!/bin/sh
curl http://localhost:8888/index.php -X POST --form-string "user_name=$1" --form-string "access_key=$2" -F "data=@-"