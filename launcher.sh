#/bin/sh
# # #
# quickCA Launcher shell script

# enable errors
set -e

# argument 1 is the filemanager you wanna use
# it is also optional...
if [ -z "$1" ]; then
	if test -n "$QC_FM"
	then
		unset QC_FM
	fi
	QC_FM="$@"
	export QC_FM
fi

# execute quickCA with env'd QC_FM or passed argument
# # as QC_FM.
if test -n "$QC_FM"
then
	./quickCA.py
else
	ARG_ONE=$@
	if [ -z "$ARG_ONE" ]; then
		echo "NO ARGUMENT PASSED. FM will be XFCEs"
		ARG_ONE="/usr/bin/thunar"
	fi

	QC_FM=${ARG_ONE} ./quickCA.py
fi

