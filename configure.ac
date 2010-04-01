dnl configure.ac                     -*- mode: autoconf -*-
dnl
dnl Copyright (c) 2005-2010 Tatsuya BIZENN, All rights reserved.

AC_PREREQ(2.54)
AC_INIT(Gauche-mcrypt, 0.1, bizenn@gmail.com)
AC_CONFIG_SRCDIR(mcrypt.stub)

AC_PATH_PROG([GOSH], gosh)
AC_PATH_PROG([GAUCHE_CONFIG], gauche-config)
AC_PATH_PROG([GAUCHE_PACKAGE], gauche-package)
AC_PATH_PROG([GAUCHE_INSTALL], gauche-install)
AC_PATH_PROG([GAUCHE_CESCONV], gauche-cesconv)
AC_PATH_PROG([LIBMCRYPT_CONFIG], libmcrypt-config)

SOEXT=`$GAUCHE_CONFIG --so-suffix`
OBJEXT=`$GAUCHE_CONFIG --object-suffix`
EXEEXT=`$GAUCHE_CONFIG --executable-suffix`
AC_SUBST(SOEXT)
AC_SUBST(OBJEXT)
AC_SUBST(EXEEXT)

AC_ARG_WITH(local,
  AC_HELP_STRING([--with-local=PATH:PATH...],
                 [For each PATH, add PATH/include to the include search
paths and PATH/lib to the library search paths.  Useful if you have some
libraries installed in non-standard places. ]),
  [
    case $with_local in
      yes|no|"") ;;  #no effect
      *) LOCAL_PATHS=$with_local ;;
    esac
  ])
AC_SUBST(LOCAL_PATHS)

ac_default_prefix=`$GAUCHE_CONFIG --prefix`

GAUCHE_PKGINCDIR=`$GAUCHE_CONFIG --pkgincdir`
GAUCHE_PKGLIBDIR=`$GAUCHE_CONFIG --pkglibdir`
GAUCHE_PKGARCHDIR=`$GAUCHE_CONFIG --pkgarchdir`
AC_SUBST(GAUCHE_PKGINCDIR)
AC_SUBST(GAUCHE_PKGLIBDIR)
AC_SUBST(GAUCHE_PKGARCHDIR)

AC_MSG_CHECKING(checking mcrypt library)
if test X${LIBMCRYPT_CONFIG} = X; then
  AC_MSG_RESULT(not available)
else
  AC_DEFINE(HAVE_LIBMCRYPT, 1)
  CPPFLAGS=`${LIBMCRYPT_CONFIG} --cflags`
  LIBS=`${LIBMCRYPT_CONFIG} --libs`
  AC_MSG_RESULT(ok)
  AC_SUBST(CPPFLAGS)
fi

GAUCHE_PACKAGE_CONFIGURE_ARGS="`echo ""$ac_configure_args"" | sed 's/[\\""\`\$]/\\\&/g'`"
AC_MSG_NOTICE([creating ${PACKAGE_NAME}.gpd])
$GAUCHE_PACKAGE make-gpd "$PACKAGE_NAME" \
  -version "$PACKAGE_VERSION" \
  -configure "./configure $GAUCHE_PACKAGE_CONFIGURE_ARGS"

echo $PACKAGE_VERSION > VERSION
AC_OUTPUT(Makefile)
