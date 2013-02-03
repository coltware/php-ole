/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2008 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id: header 252479 2008-02-07 19:39:50Z iliaa $ */

#ifndef PHP_OLE_H
#define PHP_OLE_H

#ifndef php_uint16
# if SIZEOF_SHORT == 2
#  define php_uint16 unsigned short
# else
#  define php_uint16 uint16_t
# endif
#endif

extern zend_module_entry ole_module_entry;
#define phpext_ole_ptr &ole_module_entry


#ifdef PHP_WIN32
#	define PHP_OLE_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_OLE_API __attribute__ ((visibility("default")))
#else
#	define PHP_OLE_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include <gsf/gsf-infile-msole.h>
#include <gsf/gsf-infile.h>
#include <gsf/gsf-input-stdio.h>

php_stream *php_stream_ole_open(GsfInput *input, char *mode STREAMS_DC TSRMLS_DC);

PHP_MINIT_FUNCTION(ole);
PHP_MSHUTDOWN_FUNCTION(ole);
PHP_RINIT_FUNCTION(ole);
PHP_RSHUTDOWN_FUNCTION(ole);
PHP_MINFO_FUNCTION(ole);

PHP_FUNCTION(confirm_ole_compiled);	/* For testing, remove later. */


/* 
  	Declare any global variables you may need between the BEGIN
	and END macros here:     

ZEND_BEGIN_MODULE_GLOBALS(ole)
	long  global_value;
	char *global_string;
ZEND_END_MODULE_GLOBALS(ole)
*/



#ifdef ZTS
#define OLE_G(v) TSRMG(ole_globals_id, zend_ole_globals *, v)
#else
#define OLE_G(v) (ole_globals.v)
#endif

#endif	/* PHP_OLE_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
