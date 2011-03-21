
/*
 * Copyright (C) 2011 Alexandre Kalendarev 
 *
 * akalend@mail.ru
 *
 */
#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>
#include <nginx.h>

#define NGX_HTTP_HTML_CONTENT_TYPE  "text/json"
#define NGX_HTTP_HTML_CONTENT_TYPE_LEN sizeof( NGX_HTTP_HTML_CONTENT_TYPE )
#define NGX_HTTP_HTML_NULL_RESPONCE "{[]}"
#define BUFF_SIZE 1024
#define SMALL_BUFF_SIZE 8


typedef struct {
    ngx_flag_t				enable;
	ngx_str_t				host;
	ngx_uint_t				port;
	ngx_str_t				dbname;
	ngx_str_t				tablename;
	ngx_str_t				fieldlist;
	ngx_int_t				hs_field_count;	
	ngx_str_t				indexname;	
	ngx_uint_t				limit;
	ngx_str_t				hs_command;
	ngx_str_t				hs_operation;
	ngx_int_t				variable_index;
} ngx_http_hsjson_loc_conf_t;

typedef struct {
	
	ngx_http_hsjson_loc_conf_t *	cf;	
	size_t							response_len;
	ngx_http_variable_value_t *		hs_request;
	char *							buff;			// HS read buffer
	char *							out;			// output buffer
	ngx_int_t						out_len;		// the lenght of output buffer
	int								sock;			// HS socket
} ngx_http_hsjson_ctx_t;

static void *ngx_http_hsjson_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hsjson_megre_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_conf_set_hsjson(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_hsjson_commands[] = {

    { ngx_string("hs_json"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_conf_set_hsjson,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsjson_loc_conf_t, enable),
      NULL },

    { ngx_string("hs_json_table"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsjson_loc_conf_t, tablename),
      NULL },

    { ngx_string("hs_json_db"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsjson_loc_conf_t, dbname),
      NULL },

    { ngx_string("hs_json_fields"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsjson_loc_conf_t, fieldlist),
      NULL },

    { ngx_string("hs_json_index"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsjson_loc_conf_t, indexname),
      NULL },

    { ngx_string("hs_json_op"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsjson_loc_conf_t, hs_operation),
      NULL },

    { ngx_string("hs_json_limit"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsjson_loc_conf_t, limit),
      NULL },

    { ngx_string("hs_json_host"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsjson_loc_conf_t, host),
      NULL },

    { ngx_string("hs_json_port"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsjson_loc_conf_t, port),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_hsjson_module_ctx = {
    NULL,									/* preconfiguration */
    NULL,									/* postconfiguration */

	NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_hsjson_create_loc_conf,       /* create location configuration */
    ngx_http_hsjson_megre_loc_conf         /* merge location configuration */
};



ngx_module_t  ngx_http_hsjson_module = {
    NGX_MODULE_V1,
    &ngx_http_hsjson_module_ctx,           /* module context */
    ngx_http_hsjson_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
	NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_hsjson_test_config(ngx_http_request_t *r, ngx_http_hsjson_loc_conf_t  *lcf,ngx_http_hsjson_ctx_t *ctx )
{
	if (!lcf->hs_command.len) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed coniguration. The hs_json_fieldlist is undefined.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (!lcf->tablename.len) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed coniguration. The hs_json_table is undefined.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	
	if (!lcf->dbname.len) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed coniguration. The hs_json_db is undefined.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ctx->hs_request = ngx_http_get_indexed_variable(r,lcf->variable_index);	
	if ( !ctx->hs_request->len ) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed coniguration. The variable $hs_rquest is undefined.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	
	return NGX_OK;
}

static ngx_int_t
ngx_http_hsjson_connect(ngx_http_request_t *r, ngx_http_hsjson_loc_conf_t  *lcf, int *sock)
{		
	struct sockaddr_in addr; // connector's address information 
	int rc;
	
	if(  -1 == ( *sock = socket(  AF_INET, SOCK_STREAM, IPPROTO_TCP  ) ))
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed open socket. %s", strerror(errno));
		return NGX_HTTP_SERVICE_UNAVAILABLE;
	}

	setsockopt( *sock, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(rc) );
	memset( &addr , 0, sizeof(addr) );
				
	addr.sin_family = AF_INET;
	addr.sin_port = htons (lcf->port);
	
	// addr.sin_len(  sizeof(addr) );      //undecladed
	addr.sin_addr.s_addr = inet_addr((char*)lcf->host.data); //	
	memset(addr.sin_zero, '\0', sizeof addr.sin_zero);

	if (connect(*sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed connect. %s", strerror(errno));
		return NGX_HTTP_SERVICE_UNAVAILABLE;
	}
	
	return NGX_OK;
}

static ngx_int_t
ngx_http_hsjson_open_index(ngx_http_request_t *r, ngx_http_hsjson_loc_conf_t  *lcf, ngx_http_hsjson_ctx_t *ctx)
{		
	char	buff[SMALL_BUFF_SIZE];	
	int len = write(ctx->sock, lcf->hs_command.data, lcf->hs_command.len);
		
	if ((uint)len != lcf->hs_command.len)
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Writed to HandlerSocket %d bytes from %d", len, lcf->hs_command.len);

	len = read(ctx->sock, (char*)buff, SMALL_BUFF_SIZE);
	if (len<1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed read. %s", strerror(errno));
		return NGX_HTTP_SERVICE_UNAVAILABLE;	
	}
	*(buff+len) = '\0';

	if (len > SMALL_BUFF_SIZE) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "The response command is vert long");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;	
	}

	if (strncmp((char*)buff, "0	1",3)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Parse response error. %s", buff);
		return NGX_HTTP_SERVICE_UNAVAILABLE;				
	}

//	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "*********HandlerSocket request: %s", lcf->hs_command.data);

	*(buff+len)='\0';
//	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "*********HandlerSocket response\n %s", buff);
	
	return NGX_OK;
}


static ngx_int_t
ngx_http_hsjson_read_data(ngx_http_request_t *r, ngx_http_hsjson_loc_conf_t  *lcf, ngx_http_hsjson_ctx_t *ctx) {

	char	buff[SMALL_BUFF_SIZE];	
	
	strncpy(buff, (char*)ctx->hs_request->data,ctx->hs_request->len);
	*(buff+ctx->hs_request->len) = '\0';
	
	strncpy(buff+ctx->hs_request->len+1, (char*)lcf->hs_operation.data, lcf->hs_operation.len);
	*(buff+ctx->hs_request->len+1+lcf->hs_operation.len) = '\0';
		
	int len = sprintf(ctx->buff, "0	%s	1	%s	%d\n", buff+ctx->hs_request->len+1, buff, (int)lcf->limit);

//	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "**** write to sock(%d): '%s'", len, ctx->buff);	

	len = write(ctx->sock, ctx->buff, len);
	if (!len) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Write data '%s' to sock error. %s",(u_char*) ctx->buff, strerror(errno));
		return NGX_HTTP_SERVICE_UNAVAILABLE;				
	}
	
	ctx->response_len = read(ctx->sock, (char*)ctx->buff, BUFF_SIZE);
	if (!ctx->response_len) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error read data from sock. %s", strerror(errno));
		return NGX_HTTP_SERVICE_UNAVAILABLE;				
	}	
	*(ctx->buff+ctx->response_len) = '\0';

	return NGX_OK;
}

static ngx_int_t
ngx_http_hsjson_parse(ngx_http_request_t *r, ngx_http_hsjson_ctx_t *ctx) {

	if ('0'!= *ctx->buff) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error read data from sock: '%s'", (u_char*)ctx->buff);			
		return NGX_HTTP_INTERNAL_SERVER_ERROR;						
	}

	int count = atoi((char*)ctx->buff+2);
	
	if (count != ctx->cf->hs_field_count) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Count fields if fail. %d", count);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;						
	}

	/// NULL responce
	ctx->out_len = 0;
	if (ctx->response_len == 4) {
		ctx->out_len = ngx_strlen(NGX_HTTP_HTML_NULL_RESPONCE);
		ngx_memcpy(ctx->out, NGX_HTTP_HTML_NULL_RESPONCE, ctx->out_len );		
		return NGX_OK;		
	} 

	char * p = ctx->out;

	*(p++) = '[';
	++ctx->out_len;
	
	char * p_in = ctx->buff+4;
	int len_in = 4;
	
	//TODO escape data
	
	while ( ctx->out_len < BUFF_SIZE ) {

		if (*p_in == '\n' || *p_in == '\0')
			break;
			
			*(p++) = '{';
			++ctx->out_len;

		char * p_field = (char *)ctx->cf->fieldlist.data;
		
		int field_counter = 0;
		while(field_counter++ < ctx->cf->hs_field_count) {
			
			*(p++) = '"';
			++ctx->out_len;

		 	while ( *p_field != ',' && (u_char*)p_field != ctx->cf->fieldlist.data +ctx->cf->fieldlist.len ) {	
				
				*(p++) = *(p_field++);
				++ctx->out_len;			
			}
			++p_field;	
			
			memcpy(p, "\":\"",3);		
			p += 3;
			ctx->out_len += 3;
	
		 	while ( len_in < BUFF_SIZE ) {	
				if (*p_in == '\t')
					break;
				if (*p_in == '\n')
					break;

				*(p++) = *(p_in++);
				++len_in;	
				++ctx->out_len;		
			}
			++p_in;
			++len_in;

			*(p++) = '"';
			++ctx->out_len;
			

			if (field_counter <  ctx->cf->hs_field_count) {
				*(p++) = ',';
				++ctx->out_len;
			}
																		
		}

		memcpy(p, "},",2);		
		p += 2;
		ctx->out_len += 2;		
	}
	
	*(--p) = ']'; 

	return NGX_OK;
}

static ngx_int_t
ngx_http_hsjson_handler(ngx_http_request_t *r)
{
    ngx_http_hsjson_loc_conf_t  *lcf;

	ngx_chain_t out;
	ngx_buf_t   *b;
	ngx_int_t   rc;
//	size_t		len;
	u_char		*buff;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http json handler");

	lcf = ngx_http_get_module_loc_conf(r, ngx_http_hsjson_module);

	ngx_http_hsjson_ctx_t * ctx = (ngx_http_hsjson_ctx_t*)ngx_pcalloc(r->pool, sizeof(ngx_http_hsjson_ctx_t));
	if (!ctx) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate handlersocket context.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ctx->cf = lcf;

	rc = ngx_http_hsjson_test_config(r, lcf, ctx);
	if (rc != NGX_OK)
		return rc;	

	rc = ngx_http_hsjson_connect(r, lcf, &(ctx->sock));
	if (rc != NGX_OK)
		return rc;

	rc = ngx_http_hsjson_open_index(r, lcf, ctx);
	if (rc != NGX_OK) {
			close(ctx->sock);		
			return rc;
	}
	
	buff = ngx_pcalloc(r->pool, BUFF_SIZE);
	if (!buff) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate handler socket read buffer.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ctx->buff = (char*)buff;

	rc = ngx_http_hsjson_read_data(r, lcf, ctx);
	close(ctx->sock);
		
	if (rc != NGX_OK) {	
		return rc;
	}

//	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"readed from sock\n%s", buff);
//	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"handlersocket responce_len %d", ctx->response_len);


	// Create Response
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	u_char * bb = ngx_pcalloc(r->pool, BUFF_SIZE);
	if (bb == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate chain buffer.");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ctx->out = (char *)bb;

	rc = ngx_http_hsjson_parse(r, ctx); 
	if (rc != NGX_OK) {
		return rc;
	}
	
	r->headers_out.content_type.len = NGX_HTTP_HTML_CONTENT_TYPE_LEN - 1;
	r->headers_out.content_type.data = (u_char *) NGX_HTTP_HTML_CONTENT_TYPE;
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = ctx->out_len;

	
	
		
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}	
			
	out.buf = b; 
	out.next = NULL;
	b->pos =  bb;
	b->last = bb + ctx->out_len;
	b->memory = 1;
	b->last_buf = 1;

	return ngx_http_output_filter(r, &out);
}

static char * 
ngx_conf_set_hsjson(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hsjson_handler;

    return NGX_CONF_OK;
}

static void *
ngx_http_hsjson_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hsjson_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hsjson_loc_conf_t));
	
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
	
	conf->port = NGX_CONF_UNSET_UINT;
	conf->limit = NGX_CONF_UNSET_UINT;
	
    return conf;
}

static char *
ngx_http_hsjson_megre_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	u_char *	p;
	ngx_uint_t	i;
	ngx_uint_t	len;
	u_char 		buff[256];
	
    ngx_http_hsjson_loc_conf_t *prev = parent;
    ngx_http_hsjson_loc_conf_t *conf = child;
	 	
	ngx_conf_merge_value(conf->enable, prev->enable, 0);	

	if (!conf->enable  == 0) {
			return NGX_CONF_OK;
	}

	ngx_conf_merge_str_value( conf->tablename , prev->tablename , "" );
	ngx_conf_merge_str_value( conf->dbname , prev->dbname , "" );
	ngx_conf_merge_str_value( conf->fieldlist , prev->fieldlist , "" );
	ngx_conf_merge_str_value( conf->indexname , prev->indexname , "PRIMARY" );
	ngx_conf_merge_str_value( conf->hs_operation , prev->hs_operation , "=" );

	ngx_conf_merge_uint_value( conf->limit , prev->limit , 10 );

	ngx_conf_merge_str_value( conf->host , prev->host , "127.0.0.1" );
 	ngx_conf_merge_uint_value( conf->port , prev->port , 9998 );

	conf->hs_field_count = 1;
	i = 0;
	p = conf->fieldlist.data;
	while (++i < conf->fieldlist.len) {
		if (*(++p) == ',')
			++conf->hs_field_count;
	}
		
	if (conf->fieldlist.len) {
		bzero(buff,256);
		ngx_sprintf( buff, "P\t0\t%s\t%s\t%s\t%s\n", conf->dbname.data, conf->tablename.data,conf->indexname.data,conf->fieldlist.data);			
		
		len = ngx_strlen(buff);
		p = ngx_pcalloc(cf->pool, len);
		ngx_copy(p,buff,len);
		conf->hs_command.data = p;
		conf->hs_command.len = len;
	}

	ngx_str_t str = ngx_string("hs_request");
	conf->variable_index = ngx_http_get_variable_index(cf, &str);

	if (!conf->variable_index)
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "The variable '$hs_request' is undefined");
					  
	return NGX_CONF_OK;
}
