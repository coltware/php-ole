dnl $Id$
dnl config.m4 for extension ole

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(ole, for ole support,
dnl Make sure that the comment is aligned:
dnl [  --with-ole             Include ole support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(ole, whether to enable ole support,
Make sure that the comment is aligned:
[  --enable-ole           Enable ole support])

if test "$PHP_OLE" != "no"; then
	AC_MSG_CHECKING(for pkg-config)
	
	if test ! -f "$PKG_CONFIG"; then
		PKG_CONFIG=`which pkg-config`
	fi
	
	PHP_SUBST(OLE_SHARED_LIBADD)
	PHP_NEW_EXTENSION(ole, ole.c ole_stream.c, $ext_shared)
	
	if test -f "$PKG_CONFIG"; then
		AC_MSG_RESULT(found pkg-config)
		
		if $PKG_CONFIG --exists libgsf-1; then
			AC_MSG_RESULT(found libgsf-1)
			GSF_LIBS="$LDFLAGS `$PKG_CONFIG --libs libgsf-1`"
			GSF_INCS="$CFLAGS `$PKG_CONFIG --cflags-only-I libgsf-1`"
			AC_MSG_RESULT(libgsf-1 includes $GSF_INCS)
			AC_MSG_RESULT(libgsf-1 links $GSF_LIBS)
			PHP_EVAL_INCLINE($GSF_INCS)
			PHP_EVAL_LIBLINE($GSF_LIBS, OLE_SHARED_LIBADD)
		else
			AC_MSG_RESULT(not found libgsf-1)
			AC_MSG_ERROR(Ooops ! not found libgsf-1 in the system)
		fi
	fi
fi
