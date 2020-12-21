#!/bin/bash

# ==========================
# Author: Zimskyzeng
# CreateTime: 2020-01-16
# ==========================

df -TH | tr -d "%" | awk 'NR>1&&$6>=80{print $0}' > /tmp/disk_mom.tmp

while read line
    do
        disk=`echo $line | awk '{print $7}'`
        echo "[`date '+%Y-%m-%d %H:%M:%S'`] Disk Alert! ${disk} usage is over 80%, please clean up! "
    done < /tmp/disk_mom.tmp
