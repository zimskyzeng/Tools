#!/bin/bash

# ==================================
#
# Archive Log Script
# Author: zimskyzeng
# Create Time: 2020-04-08
#
# ==================================

# ==================================
# Core Conf
#
# SET THE TIME BEFORE TODAY FOR ARCHIVE LOG
archive_time=14
# SET THE TIME BEFORE TODAY FOR DELETE LOG
delete_time=30
# SET LOG DIRECTORY
log_dir='/data/home/user00/log/'
# ==================================

home_dir='/data/home/user00/'
cache_record_file='/tmp/logfile'
cache_dir='/tmp/log_bak/'
back_dir='/data/home/user00/bak/'

current_date=`date +%Y%m%d`
current_time=`date "+%Y-%m-%d %H:%M:%S"`
backup_time=`date +%Y%m%d -d "-${archive_time}days"`

if [ -d $cache_dir ] ; then
	rm -rf $cache_dir
	mkdir -p $cache_dir
else
	mkdir -p $cache_dir
fi

function archive_tgz {
	find -L $log_dir -mtime +${archive_time} -type f > $cache_record_file
	for item in `cat $cache_record_file` ; do
		dest_file="${item/$home_dir/$cache_dir}"
		dest_dir="${dest_file%/*}"
		if [ ! -d $dest_dir ] ; then
			mkdir -p $dest_dir
			# [ $? -eq 0 ] && echo "[`date "+%Y-%m-%d %H:%M:%S"`] mkdir $dest_dir success." || exit 1
		fi
		mv -f $item $dest_file
		# [ $? -eq 0 ] && echo "[`date "+%Y-%m-%d %H:%M:%S"`] copy $item success." || exit 1
	done 

	tar zcf ${back_dir}/logbak_${backup_time}.tgz ${cache_dir}
	[ $? -eq 0 ] && echo "[`date "+%Y-%m-%d %H:%M:%S"`] Archive logbak_${current_date}.tgz success." || exit 1
	[ -d $cache_dir ] && rm -rf $cache_dir
}

function delete_old_tgz {
	local save_time=$[$delete_time-$archive_time]
	find -L $back_dir -mtime +$save_time -type f | xargs rm -f
}

function main {
	archive_tgz
	delete_old_tgz
}

main
