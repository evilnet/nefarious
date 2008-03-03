SVNSTATUS=`$1/svn status -qu .. | wc -l`

if (( $SVNSTATUS > "1" )); then
        echo WARNING
	echo ""
	echo One more more of your source files are older than what is
	echo available on SVN. It is recommended you run svn update to
	echo get the latest updates.
	echo ""
fi
