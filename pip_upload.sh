#!/bin/bash 

#rm -rf build dist *.egg-info
PYPI_URL="https://pypi.org/project/icon-getinfo/#history"
last_version=$(eval curl -s ${PYPI_URL} | grep -E -A 20 'This version' | grep -E 'release__card' | tr -d '"a-z\/=\-_<> ')
local_version=$(cat icon_getinfo/__version__.py  | grep "__version__" | awk -F '=' '{print $(NF)}' | tr -d "\' ")


if [ "${last_version}" != "${local_version}" ] ; then 
	echo "cmd ) python3 setup.py sdist bdist_wheel"
	python3 setup.py sdist bdist_wheel
else
	echo "Version Check!!"
	printf "Last Upload version : ${last_version} \n Local Version : ${local_version} \n"
	exit -1 
fi
#

read -e -p "pypi site upload ? (y/n) " ans_upload
case ${ans_upload} in 
	[Yy] | [Yn][Ee][Ss] ) 
		echo "CMD ) python3 -m twine upload dist/* --verbose"
		python3 -m twine upload dist/* --verbose
		;;
	* )
		echo "Not uplaod!"
		echo "Finished script"
		exit 0 
		;;
esac
