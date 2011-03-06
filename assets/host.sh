#!/system/bin/sh

#DIR=/data/data/org.gaeproxy

case $1 in
    add)
	
        mount -o rw,remount -t yaffs2 /dev/block/mtdblock3 /system

        cat /etc/hosts > $DIR/hosts

		echo "127.0.0.1 localhost" > /etc/hosts
        echo "$2 $3" >> /etc/hosts
        echo "" >> /etc/hosts

        mount -o ro,remount -t yaffs2 /dev/block/mtdblock3 /system
			
        ;;

    remove)

        mount -o rw,remount -t yaffs2 /dev/block/mtdblock3 /system

        cat $DIR/hosts > /etc/hosts

        mount -o ro,remount -t yaffs2 /dev/block/mtdblock3 /system

        ;;
esac
