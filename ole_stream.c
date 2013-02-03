#ifdef HAVE_CONFIG_H
#   include "config.h"
#endif
#include "php.h"
#ifdef ZEND_ENGINE_2

#include "php_streams.h"
#include "ext/standard/file.h"
#include "fopen_wrappers.h"
#include "php_ole.h"

#include "ext/standard/url.h"

#define OLE_DATA_SELF() \
	struct php_ole_stream_data_t *self = (struct php_ole_stream_data_t *) stream->abstract;

struct php_ole_stream_data_t {
  GsfInput *input;
  size_t cursor;
  php_stream *stream;
};

static size_t php_ole_ops_read(php_stream *stream, char *buf, size_t count TSRMLS_DC)
{
	OLE_DATA_SELF();

	if(self->input){
		int cur = gsf_input_tell(self->input);
		int len = gsf_input_size(self->input);

		int read_len = (int)count;
		if(read_len > len - cur){
			read_len = len - cur;
		}
		gboolean eof = gsf_input_eof(self->input);
		stream->eof = eof;
		if(eof){
			return 0;
		}

		gsf_input_read(self->input,read_len,buf);
		int size = gsf_input_tell(self->input);

		return read_len;
	}
	else{
		return 0;
	}

}

static int	php_ole_ops_close(php_stream *stream, int close_handle TSRMLS_DC)
{
	OLE_DATA_SELF();

	if(self->input)
	{
		g_object_unref ( G_OBJECT(self->input) );
		self->input = NULL;
	}

	efree(self);
	stream->abstract = NULL;
	return EOF;
}



php_stream_ops php_stream_oleio_ops = {
	NULL,	// 	write,
	php_ole_ops_read,	// 	read
	php_ole_ops_close,	// 	close
	NULL,	//	flush,
	"ole",	//	label
	NULL,		// 	seek
	NULL,		//	stat
	NULL		//	set options
};

php_stream *php_stream_ole_open(GsfInput *input, char *mode STREAMS_DC TSRMLS_DC)
{
	struct php_ole_stream_data_t *self;
	php_stream *stream = NULL;

	if( input )
	{
		self = emalloc(sizeof(*self));
		self->input = input;
		self->cursor = 0;
		self->stream = NULL;
		stream = php_stream_alloc(&php_stream_oleio_ops,self,NULL,mode);

		if(!stream){
			return NULL;
		} else {
			return stream;
		}	
	}
}

#endif /* ZEND_ENGINE_2 */

