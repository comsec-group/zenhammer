gbFile="/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages"
mnt_pnt="/mnt/huge"

if ! [ -d $mnt_pnt ]; 
then
	mkdir $mnt_pnt
fi 

echo 1 > $gbFile 
cat $gbFile
mount -t hugetlbfs  -o pagesize=1G none $mnt_pnt 
chmod a+rw $mnt_pnt
