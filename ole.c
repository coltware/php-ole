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
  | Author: coltware@gmail.com                                           |
  +----------------------------------------------------------------------+
*/

/* $Id: header 252479 2008-02-07 19:39:50Z iliaa $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/basic_functions.h"
#include "ext/standard/info.h"
#include "php_ole.h"

#include "ext/standard/sha1.h"

#ifdef Z_SET_REFCOUNT_P
# define OLE_SET_REFCOUNT_AND_IS_REF(z) \
    Z_SET_REFCOUNT_P(z, 1); \
    Z_SET_ISREF_P(z);
#else
# define OLE_SET_REFCOUNT_AND_IS_REF(z) \
    z->refcount = 1; \
    z->is_ref = 1;
#endif

#define OLE_ENCRYPTION_INFO "EncryptionInfo"

static zend_class_entry *ce_ole_infile;
static zend_class_entry *ce_ole_enc_info;

typedef struct _php_ole_infile {
	zend_object		std;
	GsfInput		*input;
	GsfInfile		*file;
	int				num;
} php_ole_infile;

typedef struct _php_ole_enc_info {
	zend_object std;
	GsfInput		*input;
	int				pos;
	char			*secret_key;
	int				secret_key_length;
	char			*verifier;
	int				verifier_length;
	char			*verifier_hash;
	int				verifier_hash_length;
} php_ole_enc_info;

typedef struct ole_enc_header1 {
	php_uint16	major;
	php_uint16	minor;
	php_uint32	flag;
} ole_enc_header1;

typedef struct ole_enc_header2 {
	php_uint32	flags;
	php_uint32	size_extra;
	php_uint32	algorithm;
	php_uint32	hash_algorithm;
	php_uint32	key_size;
	php_uint32 	provider_type;
	php_uint32	skip1;
	php_uint32	skip2;
} ole_enc_header2;

typedef struct ole_enc_header3_32 {
	php_uint32	salt_size;
	char salt[16];
	char verifier[16];
	php_uint32 verifier_hash_size;
	char verifier_hash[32];
} ole_enc_header3_32;

static void php_ole_infile_dtor(void *object TSRMLS_DC)
{
	php_ole_infile *infile = (php_ole_infile *)object;

	if (infile->file){
		g_object_unref( G_OBJECT( infile->file ));
		infile->file = NULL;
	}

	if (infile->input){
		g_object_unref(	G_OBJECT( infile->input ));
		infile->input = NULL;
	}
	zend_object_std_dtor(&infile->std TSRMLS_CC);
	efree(infile);
}

static zend_object_value php_ole_infile_new(zend_class_entry *ce TSRMLS_DC)
{
	zend_object_value retval;
	php_ole_infile *obj;
	zval *tmp;

	obj = ecalloc(1,	sizeof(*obj));
	zend_object_std_init ( &obj->std,	ce TSRMLS_CC);

#if ZEND_MODULE_API_NO >= 20100409
	object_properties_init(&obj->std,	ce);
#else
	zend_hash_copy(obj->std.properties, &ce->default_properties,
		(copy_ctor_func_t) zval_add_ref,	(void *)&tmp, sizeof(zval *));
#endif

	retval.handle = zend_objects_store_put(obj,
		(zend_objects_store_dtor_t)	zend_objects_destroy_object,
		(zend_objects_free_object_storage_t) php_ole_infile_dtor,	
		NULL	TSRMLS_CC);

	retval.handlers = zend_get_std_object_handlers();
	return retval;
}

static void php_ole_enc_info_clear(void *object)
{
	php_ole_enc_info *info = (php_ole_enc_info *)object;

	if ( info->secret_key ){
		efree(info->secret_key);
		info->secret_key = NULL;
		info->secret_key_length = 0;
	}

	if( info->verifier ){
		efree(info->verifier);
		info->verifier = NULL;
		info->verifier_length = 0;
	}

	if ( info->verifier_hash ){
		efree(info->verifier_hash);
		info->verifier_hash = NULL;
		info->verifier_hash_length = 0;
  }
}

static void php_ole_enc_info_dtor(void *object TSRMLS_DC)
{
	php_ole_enc_info *info = (php_ole_enc_info *)object;
	
	if ( info->input ){
		g_object_unref( G_OBJECT( info->input ));
		info->input = NULL;
	}

	php_ole_enc_info_clear(info);

	zend_object_std_dtor(&info->std TSRMLS_CC);
	efree(info);
}

static zend_object_value php_ole_enc_info_new(zend_class_entry *ce TSRMLS_DC)
{
	zend_object_value retval;
	php_ole_enc_info *obj;
	zval *tmp;
	
	obj = ecalloc(1,	sizeof(*obj));
	zend_object_std_init( &obj->std,	ce TSRMLS_CC);

#if ZEND_MODULE_API_NO >= 20100409
  object_properties_init(&obj->std, ce);
#else
  zend_hash_copy(obj->std.properties, &ce->default_properties,
    (copy_ctor_func_t) zval_add_ref,  (void *)&tmp, sizeof(zval *));
#endif

	retval.handle = zend_objects_store_put(obj,
		(zend_objects_store_dtor_t) zend_objects_destroy_object,
		(zend_objects_free_object_storage_t) php_ole_enc_info_dtor,
		NULL	TSRMLS_CC);

	retval.handlers = zend_get_std_object_handlers();
	return retval;
}

static PHP_METHOD(OleInfile,	__construct)
{
	zval	*object = getThis();
	php_ole_infile *infile;
	infile = (php_ole_infile *)zend_object_store_get_object(object TSRMLS_CC);

	return;
}

static PHP_METHOD(OleInfile,	open)
{
	php_ole_infile *infile = (php_ole_infile *)zend_object_store_get_object(getThis() TSRMLS_CC);
	
	char *filename = NULL;
	int argc = ZEND_NUM_ARGS();
	int filename_len;
	long mode;

	if ( zend_parse_parameters(argc TSRMLS_CC, "s|l",
		&filename,	&filename_len,
		&mode ) == FAILURE )
	{
		return;
	}

	GError *error = NULL;
	GsfInput 	*gsf_input 	= NULL;
	GsfInfile *gsf_infile = NULL;

	gsf_input = gsf_input_stdio_new(filename,&error);
	if ( gsf_input == NULL	)
	{
		RETURN_FALSE;
	}

	gsf_infile = gsf_infile_msole_new ( gsf_input, &error );
	if ( gsf_infile == NULL ){
		g_object_unref (G_OBJECT(gsf_input));
		RETURN_FALSE;
	}
	
	infile->input  = gsf_input;
	infile->file   = gsf_infile; 
	int num = gsf_infile_num_children(gsf_infile);
	infile->num = num;

	RETURN_TRUE;
}

static PHP_METHOD(OleInfile,	numChildren)
{
	php_ole_infile *infile = (php_ole_infile *)zend_object_store_get_object(getThis() TSRMLS_CC);

	if(infile->file == NULL)
	{
		RETURN_FALSE;
	}

	RETURN_LONG(infile->num);
}

static PHP_METHOD(OleInfile,	statIndex)
{
	php_ole_infile *infile = (php_ole_infile *)zend_object_store_get_object(getThis() TSRMLS_CC);
	if (infile->file == NULL)
	{
		RETURN_FALSE;
	}
	long idx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &idx) == FAILURE) {
		return;
	}
	if( idx < 0 || idx >= infile->num){
		RETURN_FALSE;
	}
	GsfInput *input = gsf_infile_child_by_index(infile->file,(int)idx);
	if(!input){
		RETURN_FALSE;
	}

	array_init(return_value);
	char *name = gsf_infile_name_by_index(infile->file,(int)idx);
	int size = gsf_input_size(input);

	add_assoc_string(return_value,"name",name,1);
	add_assoc_long(return_value,"size",size);

	g_object_unref( G_OBJECT( input ));
}

static PHP_METHOD(OleInfile,	getStreamByName)
{
	php_ole_infile *infile = (php_ole_infile *)zend_object_store_get_object(getThis() TSRMLS_CC);
	if(infile->file == NULL)
	{
		RETURN_FALSE;
	}
	char *filename;
	int filename_len;

	if ( zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
			&filename,&filename_len ) == FAILURE )
	{
		RETURN_FALSE;
	}
	GsfInput *input = gsf_infile_child_by_name(infile->file, filename);
	if( input == NULL ){
		RETURN_FALSE;
	}

	php_stream *stream;
	char *mode = "rb";

	stream = php_stream_ole_open(input, mode STREAMS_CC TSRMLS_CC);
	if(stream)
	{
		php_stream_to_zval(stream, return_value);
	}
	else{
		RETURN_FALSE;
	}

}

static PHP_METHOD(OleInfile,	getEncryptionInfo)
{
	php_ole_infile *infile = (php_ole_infile *)zend_object_store_get_object(getThis() TSRMLS_CC);
	php_ole_enc_info *info;
	
	if( infile->file == NULL )
	{
		RETURN_FALSE;
	}
	GsfInput *input = gsf_infile_child_by_name(infile->file, OLE_ENCRYPTION_INFO);
	if( input == NULL ){
		RETURN_NULL();
	}
	else{
		
		object_init_ex(return_value, ce_ole_enc_info);
		OLE_SET_REFCOUNT_AND_IS_REF(return_value);
		info = (php_ole_enc_info *)zend_object_store_get_object(return_value TSRMLS_CC);

		info->input = input;
		info->pos = 0;
		
		zend_objects_store_add_ref(getThis() TSRMLS_CC);
	}
}

const zend_function_entry ole_infile_methods[] = {
	PHP_ME(OleInfile	,__construct		,NULL	,ZEND_ACC_PUBLIC)
	PHP_ME(OleInfile	,open				,NULL	,ZEND_ACC_PUBLIC)
	PHP_ME(OleInfile	,numChildren		,NULL	,ZEND_ACC_PUBLIC)
	PHP_ME(OleInfile	,statIndex			,NULL	,ZEND_ACC_PUBLIC)
	PHP_ME(OleInfile	,getStreamByName	,NULL	,ZEND_ACC_PUBLIC)
	PHP_ME(OleInfile	,getEncryptionInfo	,NULL	,ZEND_ACC_PUBLIC)
	{NULL	,NULL	,NULL}
};

static PHP_METHOD(OleEncryptionInfo, verifyPassword)
{
	php_ole_enc_info *info = (php_ole_enc_info *)zend_object_store_get_object(getThis() TSRMLS_CC);

	if(info->input == NULL){
		RETURN_FALSE;
	}

	char *password;
	int password_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &password, &password_len) == FAILURE )
  {
      return;
  }

	php_ole_enc_info_clear(info);

	ole_enc_header1 h1;
	ole_enc_header2 h2;
	gsf_input_seek(info->input, 0, G_SEEK_SET);
	gsf_input_read(info->input,8,&h1);

	if(h1.minor != 2 || ( h1.major != 3 && h1.major != 4 )){
		RETURN_FALSE;
	}
	php_uint32 hsize;
	gsf_input_read(info->input,4,&hsize);

	gsf_input_read(info->input,32,&h2);
	//printf("[%d][%d][%d][%d][%d]\n",h2.flags,h2.size_extra,h2.algorithm,h2.hash_algorithm,h2.key_size);
	
	gsf_off_t start = gsf_input_tell(info->input);
	int l = 0;
	int next = 1;
	while(next && l < 256){
		char *ch = gsf_input_read(info->input,2,NULL);
		l+=2;
		if(ch[0] == 0 && ch[1] == 0){
			next = 0;
		}
	}
	gsf_input_seek(info->input,start,G_SEEK_SET);
	char *label = gsf_input_read(info->input,l,NULL);

	ole_enc_header3_32 h3;
	gsf_input_read(info->input,sizeof(ole_enc_header3_32),&h3);

	info->verifier = (char *)emalloc(16);
	memcpy(info->verifier,h3.verifier,16);
	info->verifier_length = 16;

	info->verifier_hash = (char *)emalloc(32);
	memcpy(info->verifier_hash,h3.verifier_hash,32);
	info->verifier_hash_length = 32;


	PHP_SHA1_CTX context;
	unsigned char digest[20];

	PHP_SHA1Init(&context);
	PHP_SHA1Update(&context, h3.salt, 16);
	PHP_SHA1Update(&context, password, password_len);
	PHP_SHA1Final(digest,&context);

	unsigned char buf[4];
	int loop = 50000;
	int i = 0;
	for(i = 0; i<loop; i++){
		buf[0] = ( i >> 0 ) & 0xFF;
		buf[1] = ( i >> 8 ) & 0xFF;
		buf[2] = ( i >> 16) & 0xFF;
		buf[3] = ( i >> 24) & 0xFF;
		PHP_SHA1Init(&context);
		PHP_SHA1Update(&context, buf, 4);
		PHP_SHA1Update(&context, digest, 20);
		PHP_SHA1Final(digest,&context);
	}

	PHP_SHA1Init(&context);
	buf[0] = ( 0 >> 0 ) & 0xFF;
	buf[1] = ( 0 >> 8 ) & 0xFF;
	buf[2] = ( 0 >> 16) & 0xFF;
	buf[3] = ( 0 >> 24) & 0xFF;

	PHP_SHA1Update(&context,digest,20);
	PHP_SHA1Update(&context,buf, 4);
	PHP_SHA1Final(digest,&context);

	unsigned char buff64[64];
	unsigned char x1[20];
	unsigned char x2[20];

	int key_size = h2.key_size / 8;
	info->secret_key = (char *)emalloc(key_size);
	info->secret_key_length = key_size;

	for( i = 0; i<64; i++ ){
		if( i < 20 ){
			buff64[i] = ( 0x36 ^ digest[i] );
		}
		else{
			buff64[i] = 0x36;
		}
	}
	PHP_SHA1Init(&context);
	PHP_SHA1Update(&context,buff64,64);
	PHP_SHA1Final(x1, &context);
	
	if(key_size > 20 ){
		for ( i = 0; i<64; i++ ){
			if( i < 20 ){
				buff64[i] = ( 0x5c ^ digest[i] );
			}
			else{
				buff64[i] = 0x5c;
			}
		}
		PHP_SHA1Init(&context);
		PHP_SHA1Update(&context,buff64,64);
		PHP_SHA1Final(x2,&context);

		memcpy(info->secret_key,x1,20);
		memcpy(info->secret_key + 20,x2,(key_size - 20));
	}
	else{
		memcpy(info->secret_key,x1,key_size);
	}

	RETURN_STRINGL(x1, key_size, 1);
}

static PHP_METHOD(OleEncryptionInfo,getSecretKey)
{
	php_ole_enc_info *info = (php_ole_enc_info *)zend_object_store_get_object(getThis() TSRMLS_CC);
	if(info->secret_key == NULL){
		RETURN_FALSE;
	}
	RETURN_STRINGL(info->secret_key,info->secret_key_length,1);
}

static PHP_METHOD(OleEncryptionInfo,getVerifier)
{
	php_ole_enc_info *info = (php_ole_enc_info *)zend_object_store_get_object(getThis() TSRMLS_CC);
	if(info->verifier == NULL){
		RETURN_FALSE;
	}
	RETURN_STRINGL(info->verifier,info->verifier_length,1);
}

static PHP_METHOD(OleEncryptionInfo,getVerifierHash)
{
	php_ole_enc_info *info = (php_ole_enc_info *)zend_object_store_get_object(getThis() TSRMLS_CC);
  if(info->verifier_hash == NULL){
    RETURN_FALSE;
  }
  RETURN_STRINGL(info->verifier_hash,info->verifier_hash_length,1);
}

const zend_function_entry ole_enc_info_methods[] = {
	PHP_ME(OleEncryptionInfo,	verifyPassword,		NULL	,ZEND_ACC_PUBLIC)
	PHP_ME(OleEncryptionInfo,	getSecretKey,		NULL	,ZEND_ACC_PUBLIC)
	PHP_ME(OleEncryptionInfo,	getVerifier, 		NULL	,ZEND_ACC_PUBLIC)
	PHP_ME(OleEncryptionInfo,	getVerifierHash, 	NULL	,ZEND_ACC_PUBLIC)
	{NULL,	NULL,	NULL}
};



/* If you declare any globals in php_ole.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(ole)
*/

/* True global resources - no need for thread safety here */
static int le_ole;

/* {{{ ole_functions[]
 *
 * Every user visible function must have an entry in ole_functions[].
 */
const zend_function_entry ole_functions[] = {
	{NULL, NULL, NULL}	/* Must be the last line in ole_functions[] */
};
/* }}} */

/* {{{ ole_module_entry
 */
zend_module_entry ole_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"ole",
	ole_functions,
	PHP_MINIT(ole),
	PHP_MSHUTDOWN(ole),
	PHP_RINIT(ole),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(ole),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(ole),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1", /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_OLE
ZEND_GET_MODULE(ole)
#endif

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("ole.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_ole_globals, ole_globals)
    STD_PHP_INI_ENTRY("ole.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_ole_globals, ole_globals)
PHP_INI_END()
*/
/* }}} */

/* {{{ php_ole_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_ole_init_globals(zend_ole_globals *ole_globals)
{
	ole_globals->global_value = 0;
	ole_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(ole)
{
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce,"OleInfile",ole_infile_methods);
	ce_ole_infile = zend_register_internal_class(&ce TSRMLS_CC);
	ce_ole_infile->create_object = php_ole_infile_new;

	INIT_CLASS_ENTRY(ce,"OleEncryptionInfo",ole_enc_info_methods);
	ce_ole_enc_info = zend_register_internal_class(&ce TSRMLS_CC);
	ce_ole_enc_info->create_object = php_ole_enc_info_new;

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(ole)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(ole)
{
	gsf_init();
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(ole)
{
	gsf_shutdown();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(ole)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "ole support", "enabled");
	php_info_print_table_end();
}
/* }}} */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
