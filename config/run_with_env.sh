#!/bin/bash

set -a
source /home/nordman/omapython/pro/mysql_siem/config/mysql.env
set +a

exec "$@"
