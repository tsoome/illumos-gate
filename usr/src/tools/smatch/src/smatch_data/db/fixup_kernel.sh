#!/bin/bash

db_file=$1
bin_dir=$(dirname $0)

FS_READ_WRITE=$(${bin_dir}/sm_hash 'fs/read_write.c')
DRIVERS_PCI_ACCESS=$(${bin_dir}/sm_hash 'drivers/pci/access.c')
DRIVERS_RAPIDIO_ACCESS=$(${bin_dir}/sm_hash 'drivers/rapidio/rio-access.c')

cat << EOF | sqlite3 $db_file
/* we only care about the main ->read/write() functions. */
delete from caller_info where function = '(struct file_operations)->read' and caller != 'vfs_read';
delete from caller_info where function = '(struct file_operations)->write' and caller != 'vfs_write';
delete from function_ptr where function = '(struct file_operations)->read';
delete from function_ptr where function = '(struct file_operations)->write';
delete from caller_info where function = '(struct file_operations)->write' and caller = 'do_loop_readv_writev';
delete from caller_info where caller = '__kernel_write';
delete from caller_info where function = 'do_splice_from' and caller = 'direct_splice_actor';
delete from caller_info where function = 'vfs_write' and type = 8017 and parameter = 0;
delete from caller_info where function = 'vfs_read' and type = 8017 and parameter = 0;

/* delete these function pointers which cause false positives */
delete from caller_info where function = '(struct file_operations)->open' and type != 0;
delete from caller_info where function = '(struct notifier_block)->notifier_call' and type != 0;
delete from caller_info where function = '(struct mISDNchannel)->send' and type != 0;
delete from caller_info where function = '(struct irq_router)->get' and type != 0;
delete from caller_info where function = '(struct irq_router)->set' and type != 0;
delete from caller_info where function = '(struct net_device_ops)->ndo_change_mtu' and caller = 'i40e_dbg_netdev_ops_write';
delete from caller_info where function = '(struct timer_list)->function' and type != 0;
delete from caller_info where function = '(struct work_struct)->func' and type != 0;

/* 8017 is USER_DATA and  9017 is USER_DATA_SET */
delete from caller_info where function = 'dev_hard_start_xmit' and type = 8017;
delete from return_states where function='vscnprintf' and type = 9017;
delete from return_states where function='scnprintf' and type = 9017;
delete from return_states where function='vsnprintf' and type = 9017;
delete from return_states where function='snprintf' and type = 9017;
delete from return_states where function='sprintf' and type = 9017;
delete from return_states where function='vscnprintf' and type = 8017;
delete from return_states where function='scnprintf' and type = 8017;
delete from return_states where function='vsnprintf' and type = 8017;
delete from return_states where function='snprintf' and type = 8017;
delete from return_states where function='sprintf' and type = 8017;
delete from return_states where function='poly1305_update' and type = 8017 and key = '\$->buflen';
/* There is something setting skb->sk->sk_mark and friends to user_data and */
/* because of recursion it gets passed to everything and is impossible to debug */
delete from caller_info where function = '__dev_queue_xmit' and type = 8017;
delete from caller_info where function = '__netdev_start_xmit' and type = 8017;
delete from caller_info where function = '(struct net_device_ops)->ndo_start_xmit' and type = 8017;
delete from caller_info where function = '(struct net_device_ops)->ndo_start_xmit' and type = 9018;
delete from caller_info where function = '(struct ieee80211_ops)->tx' and type = 8017;
delete from caller_info where function = '(struct ieee80211_ops)->tx' and type = 9018;
delete from caller_info where function = '(struct inet6_protocol)->handler' and type = 8017;
delete from caller_info where function = '(struct inet6_protocol)->handler' and type = 9018;
delete from caller_info where function = '__udp6_lib_rcv' and (type = 8017 or type = 9018);
delete from caller_info where function = 'udpv6_rcv' and (type = 8017 or type = 9018);
delete from caller_info where function = '(struct packet_type)->func' and type = 8017;
delete from caller_info where function = '(struct bio)->bi_end_io' and type = 8017;
delete from caller_info where function = '(struct mISDNchannel)->recv' and type = 8017;
delete from caller_info where type = 8017 and key = '*\$->bi_private';
delete from caller_info where type = 8017 and key = '\$->bi_private';
delete from caller_info where caller = 'NF_HOOK_COND' and type = 8017;
delete from caller_info where caller = 'NF_HOOK' and type = 8017;
delete from caller_info where caller = 'bus_for_each_drv' and type = 8017;
/* comparison doesn't deal with chunks, I guess.  */
delete from return_states where function='get_tty_driver' and type = 8017;
delete from caller_info where caller = 'snd_ctl_elem_write' and function = '(struct snd_kcontrol)->put' and type = 8017;
delete from caller_info where caller = 'snd_ctl_elem_read' and function = '(struct snd_kcontrol)->get' and type = 8017;
delete from caller_info where function = 'nf_tables_newexpr' and type = 8017 and key = '\$->family';
delete from caller_info where caller = 'fb_set_var' and function = '(struct fb_ops)->fb_set_par' and type = 8017 and parameter = 0;
delete from caller_info where caller = 'f_audio_complete' and function = '(struct usb_audio_control)->set' and type = 8017;
delete from return_states where function = 'tty_lookup_driver' and parameter = 2 and type = 8017;
delete from caller_info where function = 'iomap_apply' and type = 8017 and key = '*\$';
delete from caller_info where function = '(struct inet6_protocol)->handler' and type = 9018;
delete from caller_info where function = 'do_dentry_open param 2' and type = 8017;
delete from caller_info where function = 'do_dentry_open param 2' and type = 9018;
delete from caller_info where function = 'param_array param 7' and type = 9018;
# this is just too complicated for Smatch.  See how snd_ctl_find_id() is called.
delete from caller_info where function = 'snd_ctl_notify_one' and type = 8017;
#temporary.  Just to fix recursion
delete from caller_info where caller = 'ecryptfs_mkdir' and type = 8017;
delete from caller_info where caller = 'rpm_suspend' and type = 8017;
delete from return_states where function = 'rpm_resume' and type = 8017;

insert into caller_info values ('userspace', '', 'compat_sys_ioctl', 0, 0, 8017, 0, '\$', '1');
insert into caller_info values ('userspace', '', 'compat_sys_ioctl', 0, 0, 8017, 1, '\$', '1');
insert into caller_info values ('userspace', '', 'compat_sys_ioctl', 0, 0, 8017, 2, '\$', '1');

delete from caller_info where function = '(struct timer_list)->function' and parameter = 0;

/*
 * rw_verify_area is a very central function for the kernel.  The 1000000000
 * isn't accurate but I've picked it so that we can add "pos + count" without
 * wrapping on 32 bits.
 */
delete from return_states where function = 'rw_verify_area';
insert into return_states values ('faked', 'rw_verify_area', 0, 1, '0-1000000000[<=\$3]', 0, 0,   -1,      '', '');
insert into return_states values ('faked', 'rw_verify_area', 0, 1, '0-1000000000[<=\$3]', 0, 104,  2, '*\$', '0-1000000000');
insert into return_states values ('faked', 'rw_verify_area', 0, 1, '0-1000000000[<=\$3]', 0, 103, 3,  '\$', '0-1000000000');
insert into return_states values ('faked', 'rw_verify_area', 0, 2, '(-4095)-(-1)',     0, 0,   -1,      '', '');
update caller_info set value = '1-4096' where caller='sysfs_kf_bin_read' and function = '(struct bin_attribute)->read' and parameter = 5 and (type = 1001 or type = 8017 or type = 7016);
update caller_info set value = '1-4096' where caller='sysfs_kf_bin_write' and function = '(struct bin_attribute)->write' and parameter = 5 and (type = 1001 or type = 8017 or type = 7016);
update caller_info set value = '0-4095' where caller='sysfs_kf_bin_read' and function = '(struct bin_attribute)->read' and parameter = 4 and (type = 1001 or type = 8017 or type = 7016);
update caller_info set value = '0-4095' where caller='sysfs_kf_bin_write' and function = '(struct bin_attribute)->write' and parameter = 4 and (type = 1001 or type = 8017 or type = 7016);


delete from return_states where function = 'is_kernel_rodata';
insert into return_states values ('faked', 'is_kernel_rodata', 0, 1, '1', 0, 0,   -1,  '', '');
insert into return_states values ('faked', 'is_kernel_rodata', 0, 1, '1', 0, 103,  0,  '\$', '4096-ptr_max');
insert into return_states values ('faked', 'is_kernel_rodata', 0, 2, '0', 0, 0,   -1,  '', '');

/*
 * Other kmalloc hacking.
 */
delete from return_states where function = 'vmalloc';
insert into return_states values ('faked', 'vmalloc', 0, 1, '4096-ptr_max', 0,    0, -1, '', '');
insert into return_states values ('faked', 'vmalloc', 0, 1, '4096-ptr_max', 0, 103,  0, '\$', '1-128000000');
insert into return_states values ('faked', 'vmalloc', 0, 2, '0', 0,    0,  -1, '', '');

delete from return_states where function = 'ksize';
insert into return_states values ('faked', 'ksize', 0, 1, '0', 0,    0, -1, '', '');
insert into return_states values ('faked', 'ksize', 0, 1, '0', 0, 103,  0, '\$', '16');
insert into return_states values ('faked', 'ksize', 0, 2, '1-4000000', 0,    0,  -1, '', '');

update return_states set return = '0-8' where function = '__arch_hweight8';
update return_states set return = '0-16' where function = '__arch_hweight16';
update return_states set return = '0-32' where function = '__arch_hweight32';
update return_states set return = '0-64' where function = '__arch_hweight64';

/*
 * Preserve the value across byte swapping.  By the time we use it for math it
 * will be byte swapped back to CPU endian.
 */
update return_states set return = '0-u64max[==\$0]' where function = '__fswab64';
update return_states set return = '0-u32max[==\$0]' where function = '__fswab32';
update return_states set return = '0-u16max[==\$0]' where function = '__fswab16';
update return_states set return = '0-u64max[==\$0]' where function = '__builtin_bswap64';
update return_states set return = '0-u32max[==\$0]' where function = '__builtin_bswap32';
update return_states set return = '0-u16max[==\$0]' where function = '__builtin_bswap16';

delete from return_states where function = 'bitmap_allocate_region' and return = '1';
/* Just delete a lot of returns that everyone ignores */
delete from return_states where file = ${DRIVERS_PCI_ACCESS} and (return >= 129 and return <= 137);
delete from return_states where function = 'pci_bus_read_config_byte' and return != '0';
delete from return_states where function = 'pci_bus_read_config_word' and return != '0';
delete from return_states where function = 'pci_bus_read_config_dword' and return != '0';

/* Smatch can't parse wait_for_completion() */
update return_states set return = '(-108),(-22),0' where function = '__spi_sync' and return = '(-115),(-108),(-22)';

/* We sometimes use pre-allocated 4097 byte buffers for performance critical code but pretend it is always PAGE_SIZE */
update caller_info set value = 4096 where caller='kernfs_file_direct_read' and function='(struct kernfs_ops)->read' and type = 1002 and parameter = 1;
/* let's pretend firewire doesn't exist */
delete from caller_info where caller='init_fw_attribute_group' and function='(struct device_attribute)->show';
delete from caller_info where caller='meson_ddr_perf_format_attr_visible' and function='(struct device_attribute)->show';
delete from caller_info where caller='amdgpu_ucode_sys_visible' and function='(struct device_attribute)->show';

/* and let's fake the next dev_attr_show() call entirely */
delete from caller_info where caller='sysfs_kf_seq_show' and function='(struct sysfs_ops)->show';
insert into caller_info values ('fake', 'sysfs_kf_seq_show', '(struct sysfs_ops)->show', 0, 0, 1001, 0, '\$', '4096-ptr_max');
insert into caller_info values ('fake', 'sysfs_kf_seq_show', '(struct sysfs_ops)->show', 0, 0, 1002, 2, '\$', '4096');
insert into caller_info values ('fake', 'sysfs_kf_seq_show', '(struct sysfs_ops)->show', 0, 0, 1001, 2, '\$', '4096-ptr_max');
insert into caller_info values ('fake', 'sysfs_kf_seq_show', '(struct sysfs_ops)->show', 0, 0, 0,   -1, ''  , '');
/* config fs confuses smatch a little */
update caller_info set value = 4096 where caller='fill_read_buffer' and function='(struct configfs_item_operations)->show_attribute' and type = 1002 and parameter = 2;

/* smatch sees the memset() but not the subsequent changes */
update return_states set value = "" where function = 'gfs2_ea_find' and return = '0' and type = 101 and parameter = 3;

delete from type_value where type = '(struct fd)->file';
delete from type_value where type = '(struct fd)->flags';

/* This is sometimes an enum or a u64 */
delete from type_value where type = '(struct mc_cmd_header)->status';

/* this is handled in check_kernel.c */
delete from return_states where function = "__write_once_size";

update return_states set value = "s32min-s32max[\$1]" where function = 'atomic_set' and parameter = 0 and type = 1025;

update return_states set value = '0-u64max' where function = '_kstrtoull' and parameter = 2 and type = 1025;

/* other atomic stuff */
delete from return_states where function = 'sg_common_write' and type = 8023;
delete from return_states where function = 'schedule' and type = 8024;
delete from return_states where function = '__mutex_lock_common' and type = 8024;
delete from return_states where function = 'mutex_unlock' and type = 8024;
delete from return_states where function = 'printk' and type = 8024;
delete from return_states where function = 'vsnprintf' and type = 8024;

update return_states set return = '0-32,2147483648-2147483690' where function = '_parse_integer' and return = '0';
update return_states set value = '0-u64max' where function = '_parse_integer' and type = 1025 and parameter = 2 and key = '*$';
update return_states set value = '0-s32max' where function = 'dm_split_args' and type = 1025 and parameter = 0 and key = '*$';
update return_states set value = '(-4095)-0' where function = 'usb_submit_urb' and return ='0' and type = 1025 and parameter = 0 and key = '\$->status';

/* delete some function pointers which are sometimes byte units */
delete from caller_info where function = '(struct i2c_algorithm)->master_xfer' and type = 1027;

/* this if from READ_ONCE().  We can't know anything about the data.  */
delete from type_info where key = '(union anonymous)->__val';

/* This is RIO_BAD_SIZE */
delete from return_states where file = ${DRIVERS_RAPIDIO_ACCESS} and return = '129';

/* Smatch sucks at loops */
delete from return_states where function = 'ata_dev_next' and type = 103;

/* The problem is that parsing big function pointers is hard. */
delete from return_states where function = 'vfs_get_tree' and type = 1024;

/* Locking stuff goes here.  */
update return_states set parameter = -1, key = '\$' where function = 'ipmi_ssif_lock_cond' and type = 8020 and parameter = 1;
update return_states set parameter = 1, key = '\$->tree->tree_lock' where function = 'hfs_find_init' and type = 8020 and parameter = 0;
delete from return_states where function = '__oom_kill_process' and type = 8021;

/* These can not return NULL */
delete from return_states where function='ext4_append' and return = '0';

/* Smatch doesn't understand the allocation in genl_family_rcv_msg_attrs_parse() */
delete from type_size where type = '(struct genl_info)->attrs';

delete from return_states where function = 'fib6_tables_dump' and return = '1';

insert into function_ptr values ("fixup_kernel.sh", "r get_handler()", "ioctl_standard_call ptr param 4", 1);
insert into function_ptr values ("fixup_kernel.sh", "r get_handler()", "ioctl_standard_iw_point param 3", 1);

/* device_add() returns too many states so delete stuff */
delete from return_states where function = '__device_attach' and type = 1012;

delete from return_states where function = 'bus_for_each_dev' and return = '1';
/* This matches the wrong function pointers with the wrong data pointer. */
/* Delete it until it can be handled correctly. */
delete from caller_info where function = 'device_for_each_child' and type != 0;

/* kfree does poison stuff but it ends up being a lot of data to track all that */
delete from return_states where function = 'kfree' and (type = 501 or type = 502 or type = 1012 or type = 1025) and key = '*$';
delete from return_states where function = 'vfree' and (type = 501 or type = 502 or type = 1012 or type = 1025) and key = '*$';

/* The only work queue we care about is process_one_work() */
delete from caller_info where caller = 'cache_set_flush' and function = '(struct work_struct)->func';
delete from caller_info where caller = 'sctp_inq_push' and function = '(struct work_struct)->func';

/* dev_err() stores that dev->[class,bus,driver] is not an error pointer (useless info). */
delete from return_states where function = '__dev_printk' and type = 103;

EOF

for i in $(echo "select distinct return from return_states where function = 'clear_user';" | sqlite3 $db_file ) ; do
    echo "update return_states set return = \"$i[<=\$1]\" where return = \"$i\" and function = 'clear_user';" | sqlite3 $db_file
done

echo "select distinct file, function from function_ptr where ptr='(struct rtl_hal_ops)->set_hw_reg';" \
        | sqlite3 $db_file | sed -e 's/|/ /' | while read file function ; do

    drv=$(echo $file | perl -ne 's/.*\/rtlwifi\/(.*?)\/sw.c/$1/; print')
    if [ $drv = "" ] ; then
        continue
    fi

    echo "update caller_info
          set function = '$drv (struct rtl_hal_ops)->set_hw_reg'
          where function = '(struct rtl_hal_ops)->set_hw_reg' and file like 'drivers/net/wireless/rtlwifi/$drv/%';" \
         | sqlite3 $db_file

    echo "insert into function_ptr values ('$file', '$function', '$drv (struct rtl_hal_ops)->set_hw_reg', 1);" \
         | sqlite3 $db_file
done

for func in __kmalloc __kmalloc_track_caller __do_kmalloc_node __kmalloc_node_track_caller ; do

    cat << EOF | sqlite3 $db_file
delete from return_states where function = '$func';
insert into return_states values ('faked', '$func', 0, 1, '16', 0,    0,  -1, '', '');
insert into return_states values ('faked', '$func', 0, 1, '16', 0, 103,   0, '\$', '0');
insert into return_states values ('faked', '$func', 0, 2, '4096-ptr_max', 0,    0, -1, '', '');
insert into return_states values ('faked', '$func', 0, 2, '4096-ptr_max', 0, 103,  0, '\$', '1-4000000');
insert into return_states values ('faked', '$func', 0, 2, '4096-ptr_max', 0, 1037,  -1, '', 400);
insert into return_states values ('faked', '$func', 0, 3, '0', 0,    0,  -1, '', '');
insert into return_states values ('faked', '$func', 0, 3, '0', 0,    103,  0, '\$', '1-long_max');
EOF

done

# it's easiest to pretend that invalid kobjects don't exist
ID=$(echo "select distinct(return_id) from return_states where function = 'kobject_init' order by return_id desc limit 1;" | sqlite3 $db_file)
echo "delete from return_states where function = 'kobject_init' and return_id = '$ID';" | sqlite3 $db_file


