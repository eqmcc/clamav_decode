/* clamav-config.h.  Generated from clamav-config.h.in by configure.  */
/* clamav-config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* mmap flag for anonymous maps */
#define ANONYMOUS_MAP MAP_ANONYMOUS

/* enable bind8 compatibility */
/* #undef BIND_8_COMPAT */

/* "build clamd" */
#define BUILD_CLAMD 1

/* use ClamAuth */
/* #undef CLAMAUTH */

/* name of the clamav group */
#define CLAMAVGROUP "clamav"

/* name of the clamav user */
#define CLAMAVUSER "clamav"

/* enable debugging */
/* #undef CL_DEBUG */

/* enable experimental code */
/* #undef CL_EXPERIMENTAL */

/* thread safe */
#define CL_THREAD_SAFE 1

/* where to look for the config file */
#define CONFDIR "/usr/local/etc"

/* curses header location */
#define CURSES_INCLUDE 

/* os is aix */
/* #undef C_AIX */

/* os is beos */
/* #undef C_BEOS */

/* Increase thread stack size. */
/* #undef C_BIGSTACK */

/* os is bsd flavor */
/* #undef C_BSD */

/* os is darwin */
/* #undef C_DARWIN */

/* target is gnu-hurd */
/* #undef C_GNU_HURD */

/* os is hpux */
/* #undef C_HPUX */

/* os is interix */
/* #undef C_INTERIX */

/* os is irix */
/* #undef C_IRIX */

/* target is kfreebsd-gnu */
/* #undef C_KFREEBSD_GNU */

/* target is linux */
#define C_LINUX 1

/* os is OS/2 */
/* #undef C_OS2 */

/* os is osf/tru64 */
/* #undef C_OSF */

/* os is QNX 6.x.x */
/* #undef C_QNX6 */

/* os is solaris */
/* #undef C_SOLARIS */

/* Path to virus database directory. */
#define DATADIR "/usr/local/share/clamav"

/* "default FD_SETSIZE value" */
#define DEFAULT_FD_SETSIZE 1024

/* use fanotify */
#define FANOTIFY 1

/* whether _XOPEN_SOURCE needs to be defined for fd passing to work */
/* #undef FDPASS_NEED_XOPEN */

/* file i/o buffer size */
#define FILEBUFF 8192

/* FPU byte ordering matches CPU */
#define FPU_WORDS_BIGENDIAN 0

/* enable workaround for broken DNS servers */
/* #undef FRESHCLAM_DNS_FIX */

/* use "Cache-Control: no-cache" in freshclam */
/* #undef FRESHCLAM_NO_CACHE */

/* Define to 1 if you have the `argz_add' function. */
#define HAVE_ARGZ_ADD 1

/* Define to 1 if you have the `argz_append' function. */
#define HAVE_ARGZ_APPEND 1

/* Define to 1 if you have the `argz_count' function. */
#define HAVE_ARGZ_COUNT 1

/* Define to 1 if you have the `argz_create_sep' function. */
#define HAVE_ARGZ_CREATE_SEP 1

/* Define to 1 if you have the <argz.h> header file. */
#define HAVE_ARGZ_H 1

/* Define to 1 if you have the `argz_insert' function. */
#define HAVE_ARGZ_INSERT 1

/* Define to 1 if you have the `argz_next' function. */
#define HAVE_ARGZ_NEXT 1

/* Define to 1 if you have the `argz_stringify' function. */
#define HAVE_ARGZ_STRINGIFY 1

/* attrib aligned */
#define HAVE_ATTRIB_ALIGNED 1

/* attrib packed */
#define HAVE_ATTRIB_PACKED 1

/* have bzip2 */
/* #undef HAVE_BZLIB_H */

/* Define to 1 if you have the `closedir' function. */
#define HAVE_CLOSEDIR 1

/* Define to 1 if you have the `ctime_r' function. */
#define HAVE_CTIME_R 1

/* ctime_r takes 2 arguments */
#define HAVE_CTIME_R_2 1

/* ctime_r takes 3 arguments */
/* #undef HAVE_CTIME_R_3 */

/* Define to 1 if you have the declaration of `cygwin_conv_path', and to 0 if
   you don't. */
/* #undef HAVE_DECL_CYGWIN_CONV_PATH */

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define if you have the GNU dld library. */
/* #undef HAVE_DLD */

/* Define to 1 if you have the <dld.h> header file. */
/* #undef HAVE_DLD_H */

/* Define to 1 if you have the `dlerror' function. */
#define HAVE_DLERROR 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <dl.h> header file. */
/* #undef HAVE_DL_H */

/* Define if you have the _dyld_func_lookup function. */
/* #undef HAVE_DYLD */

/* Define to 1 if you have the `enable_extended_FILE_stdio' function. */
/* #undef HAVE_ENABLE_EXTENDED_FILE_STDIO */

/* Define to 1 if the system has the type `error_t'. */
#define HAVE_ERROR_T 1

/* have working file descriptor passing support */
#define HAVE_FD_PASSING 1

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
#define HAVE_FSEEKO 1

/* have getaddrinfo() */
#define HAVE_GETADDRINFO 1

/* Define to 1 if getpagesize() is available */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* iconv() available */
#define HAVE_ICONV 1

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `initgroups' function. */
#define HAVE_INITGROUPS 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* in_addr_t is defined */
#define HAVE_IN_ADDR_T 1

/* in_port_t is defined */
#define HAVE_IN_PORT_T 1

/* Define to '1' if you have the check.h library */
#define HAVE_LIBCHECK 1

/* Define if you have the libdl library or equivalent. */
#define HAVE_LIBDL 1

/* Define if libdlloader will be built on this platform */
#define HAVE_LIBDLLOADER 1

/* Define to 1 if you have the <libmilter/mfapi.h> header file. */
/* #undef HAVE_LIBMILTER_MFAPI_H */

/* Define to '1' if you have the ncurses.h library */
/* #undef HAVE_LIBNCURSES */

/* Define to '1' if you have the curses.h library */
/* #undef HAVE_LIBPDCURSES */

/* Define to 1 if you have the `z' library (-lz). */
#define HAVE_LIBZ 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define this if a modern libltdl is already installed */
/* #undef HAVE_LTDL */

/* Define to 1 if you have the <mach-o/dyld.h> header file. */
/* #undef HAVE_MACH_O_DYLD_H */

/* Define to 1 if you have the `madvise' function. */
#define HAVE_MADVISE 1

/* Define to 1 if you have the `mallinfo' function. */
#define HAVE_MALLINFO 1

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the `memcpy' function. */
#define HAVE_MEMCPY 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `mkstemp' function. */
#define HAVE_MKSTEMP 1

/* Define to 1 if you have a working `mmap' system call that supports
   MAP_PRIVATE. */
#define HAVE_MMAP 1

/* Define to 1 if you have the <ndir.h> header file. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the `opendir' function. */
#define HAVE_OPENDIR 1

/* Define to 1 if you have the `poll' function. */
#define HAVE_POLL 1

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* "pragma pack" */
/* #undef HAVE_PRAGMA_PACK */

/* "pragma pack hppa/hp-ux style" */
/* #undef HAVE_PRAGMA_PACK_HPPA */

/* Define if libtool can extract symbol lists from object files. */
#define HAVE_PRELOADED_SYMBOLS 1

/* Define to 1 if you have the `pthread_yield' function. */
#define HAVE_PTHREAD_YIELD 1

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have the `readdir' function. */
#define HAVE_READDIR 1

/* readdir_r takes 2 arguments */
/* #undef HAVE_READDIR_R_2 */

/* readdir_r takes 3 arguments */
/* #undef HAVE_READDIR_R_3 */

/* Define to 1 if you have the `recvmsg' function. */
#define HAVE_RECVMSG 1

/* have resolv.h */
#define HAVE_RESOLV_H 1

/* Define signed right shift implementation */
#define HAVE_SAR 1

/* Define to 1 if you have the `sched_yield' function. */
#define HAVE_SCHED_YIELD 1

/* Define to 1 if you have the `sendmsg' function. */
#define HAVE_SENDMSG 1

/* Define to 1 if you have the `setgroups' function. */
#define HAVE_SETGROUPS 1

/* Define to 1 if you have the `setsid' function. */
#define HAVE_SETSID 1

/* Define if you have the shl_load function. */
/* #undef HAVE_SHL_LOAD */

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* enable stat64 */
#define HAVE_STAT64 1

/* Define to 1 if you have the <stdbool.h> header file. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasestr' function. */
#define HAVE_STRCASESTR 1

/* Define to 1 if you have the `strerror_r' function. */
#define HAVE_STRERROR_R 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if sysconf(_SC_PAGESIZE) is available */
#define HAVE_SYSCONF_SC_PAGESIZE 1

/* Define to 1 if you have the <sys/dl.h> header file. */
/* #undef HAVE_SYS_DL_H */

/* Define to 1 if you have the <sys/filio.h> header file. */
/* #undef HAVE_SYS_FILIO_H */

/* Define to 1 if you have the <sys/inttypes.h> header file. */
/* #undef HAVE_SYS_INTTYPES_H */

/* Define to 1 if you have the <sys/int_types.h> header file. */
/* #undef HAVE_SYS_INT_TYPES_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* "have <sys/select.h>" */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/times.h> header file. */
#define HAVE_SYS_TIMES_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H 1

/* Define this if uname(2) is POSIX */
#define HAVE_UNAME_SYSCALL 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* This value is set to 1 to indicate that the system argz facility works */
#define HAVE_WORKING_ARGZ 1

/* For internal use only - DO NOT DEFINE */
/* #undef HAVE__INTERNAL__SHA_COLLECT */

/* "Full library version number" */
#define LIBCLAMAV_FULLVER "6.1.11"

/* "Major library version number" */
#define LIBCLAMAV_MAJORVER 6

/* Define if the OS needs help to load dependent libraries for dlopen(). */
/* #undef LTDL_DLOPEN_DEPLIBS */

/* Define to the system default library search path. */
#define LT_DLSEARCH_PATH "/lib:/usr/lib:/usr/lib/mesa:/lib/i386-linux-gnu:/usr/lib/i386-linux-gnu:/lib/i686-linux-gnu:/usr/lib/i686-linux-gnu:/usr/lib/alsa-lib:/usr/local/lib:/usr/lib/vmware-tools/lib32/libvmGuestLib.so:/usr/lib/vmware-tools/lib64/libvmGuestLib.so:/usr/lib/vmware-tools/lib32/libvmGuestLibJava.so:/usr/lib/vmware-tools/lib64/libvmGuestLibJava.so:/usr/lib/vmware-tools/lib32/libDeployPkg.so:/usr/lib/vmware-tools/lib64/libDeployPkg.so"

/* The archive extension */
#define LT_LIBEXT "a"

/* The archive prefix */
#define LT_LIBPREFIX "lib"

/* Define to the extension used for runtime loadable modules, say, ".so". */
#define LT_MODULE_EXT ".so"

/* Define to the name of the environment variable that determines the run-time
   module search path. */
#define LT_MODULE_PATH_VAR "LD_LIBRARY_PATH"

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Define to the shared library suffix, say, ".dylib". */
/* #undef LT_SHARED_EXT */

/* disable assertions */
#define NDEBUG 1

/* Define if dlsym() requires a leading underscore in symbol names. */
/* #undef NEED_USCORE */

/* bzip funtions do not have bz2 prefix */
#define NOBZ2PREFIX 1

/* "no fd_set" */
/* #undef NO_FD_SET */

/* Name of package */
#define PACKAGE PACKAGE_NAME

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "http://bugs.clamav.net/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "ClamAV"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "ClamAV devel"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "clamav"

/* Define to the home page for this package. */
#define PACKAGE_URL "http://www.clamav.net/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "devel"

/* scan buffer size */
#define SCANBUFF 131072

/* Define to 1 if the `setpgrp' function takes no argument. */
#define SETPGRP_VOID 1

/* The number of bytes in type int */
#define SIZEOF_INT 4

/* The number of bytes in type long */
#define SIZEOF_LONG 4

/* The number of bytes in type long long */
#define SIZEOF_LONG_LONG 8

/* The number of bytes in type short */
#define SIZEOF_SHORT 2

/* The number of bytes in type void * */
#define SIZEOF_VOID_P 4

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Support for IPv6 */
#define SUPPORT_IPv6 1

/* enable memory pools */
#define USE_MPOOL 1

/* use syslog */
#define USE_SYSLOG 1

/* Version number of package */
#define VERSION "devel-20121126"

/* Version suffix for package */
#define VERSION_SUFFIX ""

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
/* #undef _LARGEFILE_SOURCE */

/* POSIX compatibility */
/* #undef _POSIX_PII_SOCKET */

/* thread safe */
#define _REENTRANT 1

/* thread safe */
/* #undef _THREAD_SAFE */

/* Define so that glibc/gnulib argp.h does not typedef error_t. */
/* #undef __error_t_defined */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to a type to use for `error_t' if it is not otherwise available. */
/* #undef error_t */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to the equivalent of the C99 'restrict' keyword, or to
   nothing if this is not supported.  Do not define if restrict is
   supported directly.  */
#define restrict __restrict
/* Work around a bug in Sun C++: it does not support _Restrict or
   __restrict__, even though the corresponding Sun C compiler ends up with
   "#define restrict _Restrict" or "#define restrict __restrict__" in the
   previous line.  Perhaps some future version of Sun C++ will work with
   restrict; if so, hopefully it defines __RESTRICT like Sun C does.  */
#if defined __SUNPRO_CC && !defined __RESTRICT
# define _Restrict
# define __restrict__
#endif

/* Define to "int" if <sys/socket.h> does not define. */
/* #undef socklen_t */

#include "platform.h"
