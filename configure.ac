AC_PREREQ([2.71])
AC_INIT([dosattrib],[1.0],[pen@lysator.liu.se],[dosattrib],[https://github.com/ptrrkssn/dosattrib])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_SRCDIR([dosattrib.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for header files.
AC_CHECK_HEADERS([sys/xattr.h sys/extattr.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([strdup strerror])
AC_CHECK_FUNCS([extattr_get_link lgetxattr getxattr extattr_set_link lsetxattr setxattr extattr_delete_link removexattr attropen])

AC_CONFIG_FILES([Makefile pkgs/Makefile pkgs/Makefile.port pkgs/dosattrib.rb pkgs/pkginfo pkgs/dosattrib.spec pkgs/pkg-descr pkgs/build.sh pkgs/control])
AC_OUTPUT
