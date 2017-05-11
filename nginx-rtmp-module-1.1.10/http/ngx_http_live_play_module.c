#include "ngx_http_live_play_module.h"
#include "ngx_http_rtmp_live_module.h"
#include "ngx_rtmp_to_flv_packet.h"

static char * ngx_http_live_play_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static void * ngx_http_live_play_create_srv_conf(ngx_conf_t * cf);
static void * ngx_http_live_play_create_loc_conf(ngx_conf_t * cf);
static char * ngx_http_live_play_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char * ngx_http_live_play_set(ngx_conf_t * cf,ngx_command_t * cmd,void* conf);
static char * ngx_http_live_play_set_domain(ngx_conf_t * cf,ngx_command_t * cmd,void* conf);

static ngx_int_t ngx_http_live_play_handler(ngx_http_request_t * r);

static void ngx_http_live_play_send_header_ev(ngx_event_t *ev);

static ngx_command_t  ngx_http_live_play_commands[] = {
     { ngx_string("http_live"),
        NGX_HTTP_LOC_CONF |NGX_CONF_FLAG,
		ngx_http_live_play_set,
		NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_live_on), 
        NULL },
        
     { ngx_string("http_play_domain"),
		NGX_HTTP_LOC_CONF |NGX_CONF_FLAG,
		ngx_http_live_play_set_domain,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_live_play_loc_conf_t,http_domain_on), 
		NULL},

     { ngx_string("live_md5_check"),
		NGX_HTTP_LOC_CONF |NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_live_play_loc_conf_t,live_md5_check_on), 
		NULL},

      {ngx_string("md5_key"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,live_md5_key), 
        NULL},

        {ngx_string("http_send_timeout"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_send_timeout),//default NGX_HTTP_PULL_KEEPALIVE_TIMEOUT
		NULL},

        {ngx_string("send_http_header_timeout"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_send_header_timeout),//default NGX_HTTP_PULL_KEEPALIVE_TIMEOUT
		NULL},

        {ngx_string("http_send_chunk_size"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_send_chunk_size),//default NGX_HTTP_PULL_KEEPALIVE_TIMEOUT
		NULL},

        {ngx_string("http_send_max_chunk_count"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_send_max_chunk_count),//default NGX_HTTP_PULL_KEEPALIVE_TIMEOUT
		NULL},
      ngx_null_command
};

static ngx_http_module_t  ngx_http_live_play_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_http_live_play_create_srv_conf,    /* create server configuration */
    ngx_http_live_play_merge_srv_conf,     /* merge server configuration */

    ngx_http_live_play_create_loc_conf,       /* create location configuration */
    ngx_http_live_play_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_live_play_module = {
    NGX_MODULE_V1,
    &ngx_http_live_play_module_ctx,         /* module context */
    ngx_http_live_play_commands,            /* module directives */
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



ngx_http_flv_frame_t * 
alloc_http_flv_frame(ngx_http_live_play_request_ctx_t *s)
{
    ngx_http_flv_frame_t * node = NULL;
    if (s && s->s) {
        ngx_pool_t   * pool = s->s->pool; 
        if (s->frame_free) {
            node = s->frame_free;
            s->frame_free = node->next;
            node->next = NULL;
        } else {
            if (pool)
                node = (ngx_http_flv_frame_t*)ngx_palloc(pool, sizeof(ngx_http_flv_frame_t));
        }
        if (node) {
            memset(node,0,sizeof(ngx_http_flv_frame_t));
        }
    }
    return node;
}

void 
free_http_flv_frame(ngx_http_live_play_request_ctx_t *s,ngx_http_flv_frame_t *frame)
{
    if (s && s->frame_free && frame) {
        memset(frame,0,sizeof(ngx_http_flv_frame_t));
        frame->next = s->frame_free;
        s->frame_free = frame;
    }
}

static char * 
ngx_http_live_play_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_live_play_srv_conf_t *prev = (ngx_http_live_play_srv_conf_t*)parent;
    ngx_http_live_play_srv_conf_t *conf = (ngx_http_live_play_srv_conf_t*)child;
    ngx_conf_merge_str_value(conf->server,prev->server,"");
	return NGX_CONF_OK;
}

static void * 
ngx_http_live_play_create_srv_conf(ngx_conf_t * cf)
{
	ngx_http_live_play_srv_conf_t * conf;

	conf = (ngx_http_live_play_srv_conf_t*)ngx_pcalloc(cf->pool,sizeof(*conf));
	if (conf == NULL) {
		return NULL;
	}
    return conf;
}

static void * 
ngx_http_live_play_create_loc_conf(ngx_conf_t * cf)
{
	ngx_http_live_play_loc_conf_t * conf;

	conf = (ngx_http_live_play_loc_conf_t*)ngx_pcalloc(cf->pool,sizeof(ngx_http_live_play_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}
    conf->http_live_on = NGX_CONF_UNSET;
    conf->http_domain_on = NGX_CONF_UNSET;
    conf->live_md5_check_on = NGX_CONF_UNSET;
    conf->http_send_timeout = NGX_CONF_UNSET_MSEC; 
    conf->http_send_header_timeout = NGX_CONF_UNSET_MSEC; 
    conf->http_send_max_chunk_count = NGX_CONF_UNSET_UINT;
    conf->http_send_chunk_size = NGX_CONF_UNSET_UINT;
    return conf;
}

static char * 
ngx_http_live_play_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_live_play_loc_conf_t *prev = (ngx_http_live_play_loc_conf_t*)parent;
    ngx_http_live_play_loc_conf_t *conf = (ngx_http_live_play_loc_conf_t*)child;

    ngx_conf_merge_value(conf->http_live_on,prev->http_live_on, 0);
    ngx_conf_merge_value(conf->http_domain_on,prev->http_domain_on, 0);
    ngx_conf_merge_value(conf->live_md5_check_on,prev->live_md5_check_on, 0);
    ngx_conf_merge_str_value(conf->live_md5_key,prev->live_md5_key,"");
    ngx_conf_merge_msec_value(conf->http_send_timeout, prev->http_send_timeout,10000); 
    ngx_conf_merge_msec_value(conf->http_send_header_timeout, prev->http_send_header_timeout,5000); 
    
    ngx_conf_merge_uint_value(conf->http_send_chunk_size,prev->http_send_chunk_size,4096);
    ngx_conf_merge_uint_value(conf->http_send_max_chunk_count,prev->http_send_max_chunk_count,256);

    return NGX_CONF_OK;
}

static char * 
ngx_http_live_play_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t            *clcf;

	clcf = (ngx_http_core_loc_conf_t*)ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
	
	ngx_http_live_play_loc_conf_t * ploc = (ngx_http_live_play_loc_conf_t*)conf;
	ngx_conf_set_flag_slot(cf,cmd,&ploc->http_live_on);
	if (!ploc->http_live_on) {
		return NGX_CONF_OK;
	}
    	
	clcf->handler = ngx_http_live_play_handler;

	return NGX_CONF_OK;
}

static char * 
ngx_http_live_play_set_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return NGX_CONF_OK;
}

void 
ngx_str_format_string(ngx_str_t str, char *buf)
{
    strncpy(buf, (const char*)str.data, str.len);
    buf[str.len+1] = '\0';
}

static ngx_int_t 
ngx_http_parse_play_uri(ngx_str_t uri, ngx_http_live_play_request_ctx_t *pr)
{
    if (pr == NULL)
        return NGX_ERROR;

    char* p = (char*)uri.data;
    ngx_uint_t len = 0;
    if (*p != '/'){
        printf("uri format error!\n");
    } else {
        //获取 app
        p += 1;
        len += 1;
        pr->app.data = (u_char*)p;
        while (len <= uri.len){
            if (*p == '/') {
                break;
            }
            pr->app.len++;
            len++;
            p++;
        }
        if (len >= uri.len) {
            return NGX_ERROR;
        } else {
            //获取stream
            p += 1;
            len += 1;
            pr->stream.data = (u_char*)p;
            while(len <= uri.len){
                if(*p == '?'){
                    break;
                }
                if(*p == '.'){
                    pr->suffix.data = (u_char*)(p + 1);
                    pr->suffix.len = pr->stream.len;
                }
                pr->stream.len++;
                len++;
                p++;
            }
            if(pr->suffix.len > 0){
                ngx_uint_t l = pr->suffix.len;
                pr->suffix.len = pr->stream.len - l - 1;
                pr->stream.len = l;
            }
        }
    }
    return NGX_OK;
}

static ngx_int_t 
ngx_parse_args(ngx_http_request_t *r, ngx_http_live_play_request_ctx_t *pr)
{
    char* p = (char*)r->args.data;
    char *pkb , *pkd ;
    ngx_uint_t len = 0;
    if (r->args.len <= 0)
        return NGX_OK;
    pkb = pkd = p;
    while (len <= r->args.len) {
        if(*p == '&' || len == r->args.len)
        {
            if(pkd != pkb){
                ngx_str_map_list_t *param_node = (ngx_str_map_list_t*)ngx_pcalloc(r->pool,sizeof(ngx_str_map_list_t));
                ngx_str_map_node_t * node = (ngx_str_map_node_t*)ngx_pcalloc(r->pool,sizeof(ngx_str_map_node_t));
                if(node == NULL ||  param_node == NULL)
                    return NGX_ERROR;

                node->key.data = (u_char*)pkb;
                node->key.len = (ngx_uint_t)(pkd - pkb);
                node->value.data = (u_char*)pkd+1;
                node->value.len = (ngx_uint_t)(p - pkd - 1);

                param_node->node = node;
                param_node->next = NULL;
            
                if(pr->param_list_head == NULL){
                    pr->param_list_tail = pr->param_list_head = param_node;
                }else{
                    pr->param_list_tail->next =param_node;
                    pr->param_list_tail = param_node;
                }

                if(len < r->args.len)
                    pkb = p+1;

            }else {
                break;
            }
        }
        else if(*p == '=')
        {
            pkd = p;
        }
        len++;
        p++;
    }

    ngx_str_map_list_t *list = pr->param_list_head;
    while(list)
    {
        ngx_str_map_node_t * node = list->node;
        if(node)
        {
            char szKey[128] = {'\0'};
            char szValue[512] = {'\0'};
            ngx_str_format_string(node->key,szKey);
            ngx_str_format_string(node->value,szValue);
            printf("param  %s=%s\n",szKey,szValue);
        }   
        list = list->next;
    }
    return NGX_OK;
}

static void 
ngx_http_live_play_close_request(ngx_http_request_t * r)
{
    ngx_http_live_play_request_ctx_t *  pr = (ngx_http_live_play_request_ctx_t*)ngx_http_get_module_ctx(r,ngx_http_live_play_module);	
      
    if (pr->send_header_timeout_ev.timer_set) {
        ngx_del_timer(&pr->send_header_timeout_ev);
    }

    // 获取日志唯一id
    u_char session[32] = {'\0'};
    ngx_sprintf(session, "%l_%d", pr->current_ts, r->connection->fd);

    char *szformat = NULL;
    szformat = "{_type:v2.edgePullStop,timestamp:%l,session:%s,clientIP:%V,serverIP:%V,host:%V,name:%V,protocolType:http-flv,pullUrl:%V,duration:%l,statusCode:%s,videoSize:%l,audioSize:%l,allDropFrame:%l}";
    ngx_log_error(NGX_LOG_ERR, global_log, 0, szformat, pr->current_ts, session, &pr->client_ip, &pr->server_ip, &pr->host, &pr->stream, &pr->pull_url, pr->current_ts-pr->request_ts, "NGX_OK",pr->video_size, pr->audio_size, pr->dropVideoFrame);
    
    //删除
    ngx_http_rtmp_live_close_play_stream((void*)pr);
    
    if(pr->frame_chain_head)
    {
        ngx_http_flv_frame_t *frame = pr->frame_chain_head;
        while(frame)
        {
            ngx_http_flv_free_tag_mem(frame->out);
            frame->out = NULL;
            if(pr->frame_chain_head)
            {
                frame = pr->frame_chain_head->next;
                pr->frame_chain_head = frame->next;
            }
            else
                break;
        }
    }
    pr->frame_chain_head = pr->frame_chain_tail = NULL;

    r->connection->destroyed = 1;
    if(r->connection->write != NULL && r->connection->write->timer_set)
		ngx_del_timer(r->connection->write);

    ngx_http_set_ctx(r,NULL,ngx_http_live_play_module);
    printf("r->count %d   r->keepalive %d\n",r->count,r->keepalive);
    r->keepalive = 0;
	ngx_http_finalize_request(r,NGX_DONE);
}

static void 
ngx_http_live_play_close_session_handler(ngx_event_t *e)
{
    ngx_http_request_t *  r = e->data;
    if(r != NULL)
        ngx_http_live_play_close_request(r);   
}

void 
ngx_http_live_play_close(void * v)
{
    ngx_http_live_play_request_ctx_t *  hctx  = (ngx_http_live_play_request_ctx_t*)v;

    ngx_event_t        *e;
    ngx_connection_t   *c;
    if(hctx == NULL)
        return;

    c = hctx->s->connection;
    if (c->destroyed) {
        return;
    }
    printf("ngx_http_live_play_close  set close event \n");

    c->destroyed = 1;
    e = &hctx->close;
    e->data = hctx->s;
    e->handler = ngx_http_live_play_close_session_handler;
    e->log = c->log;
    ngx_post_event(e, &ngx_posted_events);
}

static ngx_int_t 
ngx_http_live_authentication(ngx_http_live_play_request_ctx_t * r)
{
    ngx_http_live_play_loc_conf_t                   *hlplc;
    
    hlplc = (ngx_http_live_play_loc_conf_t*)ngx_http_get_module_loc_conf(r->s, ngx_http_live_play_module);
    if (hlplc == NULL)
        return NGX_ERROR;

    if (hlplc->live_md5_check_on) {
        if (hlplc->live_md5_key.len <= 0 || r->param_list_head == NULL)
            return NGX_ERROR;
    }
    return NGX_OK;
}

static void 
ngx_http_live_play_recv_handler(ngx_event_t *ev)
{
    printf("ngx_http_live_play_recv_handler \n");
    ngx_connection_t * c = (ngx_connection_t *)ev->data;  
    if (c== NULL)
        return;

    ngx_int_t n;

    u_char buf[512];
    while (1) {
        n = c->recv(c, buf, sizeof(buf));
        if (n == NGX_ERROR || n == 0) {
            ev->error = 1;
            printf("close in read +++++++++++1\n");
            break;
        }

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                printf("close in read ------------2\n");
                ev->error = 1;
                break;
            } else {
                return;
            }
        }
        if (n < 0)
            break;
    }
    printf("close http request %lx\n",(unsigned long)c->data);
    ngx_http_request_t *  r = (ngx_http_request_t * )c->data;
    ngx_http_live_play_close_request(r);
}

static void 
ngx_http_live_play_write_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c = (ngx_connection_t*)ev->data;
    ngx_http_request_t  *r = (ngx_http_request_t*)c->data;
	ngx_http_live_play_request_ctx_t *hctx = (ngx_http_live_play_request_ctx_t*)ngx_http_get_module_ctx(r,ngx_http_live_play_module);	
     ngx_http_live_play_loc_conf_t* hlplc = NULL;
    hlplc = (ngx_http_live_play_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_live_play_module);
    ngx_int_t                   n;
    printf("ngx_http_live_play_write_handler global_log:%p\n", global_log);
    if (c->destroyed){
        ev->error = 1;
        return;
    }
	if (ev->error != 0){
        ngx_http_live_play_close_request(r);
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_live_play:write handler event error");
		return;
	}

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_live_client timed out");
        c->timedout = 1;
        ngx_http_live_play_close_request(r);
        return;
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }


    if (hctx->frame_chain_head) {
        // 取一帧发送
        ngx_http_flv_frame_t *frame = hctx->frame_chain_head;
        hctx->frame_chain_head = frame->next;
        frame->next = NULL;
        while (frame) {
            // 发送大小
            ngx_uint_t send_len = frame->out->buf->last - frame->out->buf->pos;
            while (send_len > 0) {
                ngx_int_t send_one_len = hlplc->http_send_chunk_size > send_len ? send_len : hlplc->http_send_chunk_size;
                n = c->send(c, frame->out->buf->pos,send_one_len); 

                if (n == NGX_AGAIN || n == 0 
                        || (n < send_one_len && n > 0 )
                        || hctx->current_send_count > hlplc->http_send_max_chunk_count ) {
                    hctx->current_send_count  = 0;
                    
                    if(n > 0 &&  n <= send_one_len)
                        frame->out->buf->pos += n;

                    frame->next = hctx->frame_chain_head;
                    hctx->frame_chain_head = frame;

                    ngx_add_timer(c->write, hlplc->http_send_timeout);
                    printf("ngx_handle_write_event ################ %lx %lx\n",(unsigned long)frame,(unsigned long)frame->out);
                    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                        ngx_http_live_play_close_request(r);
                    }
                    return;
                } else {
                    
                    if (n < 0) {
                        ngx_http_live_play_close_request(r);
                        printf("ngx_handle_write_event send data fail\n");
                        return;
                    }
                    hctx->current_send_count++;
                    frame->out->buf->pos += n;
                    send_len -= n;
                }
            }
            
            hctx->current_send_count = 0;
            
            ngx_http_flv_free_tag_mem(frame->out);
            frame->out = NULL;
            free_http_flv_frame(hctx,frame);
            frame = NULL;
            
            if (hctx->frame_chain_head) {
                frame =  hctx->frame_chain_head;
                hctx->frame_chain_head = frame->next;
                frame->next = NULL;
            }
            if (hctx->frame_chain_head == NULL) {
                hctx->frame_chain_head = hctx->frame_chain_tail = NULL;
            }
        }
    }

    if (ev->active) {
        ngx_del_event(ev, NGX_WRITE_EVENT, 0);
    }
}

static ngx_int_t 
ngx_http_live_play_respond_header(ngx_http_live_play_request_ctx_t *r, 
        ngx_http_respond_henader_status ret, const char *content_type, const char *location)
{
	ngx_uint_t index = (ngx_int_t)ret;
	
    index = index < sizeof(ngx_http_live_play_status) / sizeof(char*) ? index : 0;
    char * szformat = NULL;
    if (ret == HTTP_STATUS_302) {
        szformat = "HTTP/1.1 %s\r\n"
		            "Server: "NGINX_VER"\r\n"
		            "Date: %V\r\n"
                    "Cache-Control: no-cache\r\n"
		            "Content-Type: %s\r\n"
                    "Location: %s\r\n"
		            "Connection: close\r\n\r\n";
    } else {
	    szformat = "HTTP/1.1 %s\r\n"
		            "Server: "NGINX_VER"\r\n"
		            "Date: %V\r\n"
                    "Cache-Control: no-cache\r\n"
		            "Content-Type: %s\r\n"
		            "Connection: close\r\n\r\n";
    }
    
    r->s->connection->write->handler = ngx_http_live_play_write_handler;
    r->s->connection->write->data = r->s->connection;
    
	const ngx_int_t buf_len  = 1024;
	r->header_chain->buf = ngx_pcalloc(r->s->connection->pool, sizeof(ngx_buf_t));
    if (r->header_chain->buf == NULL) {
        return NGX_ERROR;
    }
	r->header_chain->buf->start = r->header_chain->buf->pos = (u_char*)ngx_palloc(r->s->connection->pool,buf_len);
	r->header_chain->buf->end = r->header_chain->buf->start + buf_len;
	r->header_chain->buf->tag = NULL;
    r->header_chain->buf->memory = 1;

    if (HTTP_STATUS_302 == ret) {
        r->header_chain->buf->last = ngx_snprintf(r->header_chain->buf->pos, buf_len, szformat, 
                ngx_http_live_play_status[index].rs, &ngx_cached_http_time, content_type, location);
    } else {
        r->header_chain->buf->last = ngx_snprintf(r->header_chain->buf->pos, buf_len, szformat,
                ngx_http_live_play_status[index].rs, &ngx_cached_http_time, content_type);
    }
    //    printf("%s\n",r->header_chain->buf->pos);
    r->s->header_sent = 1;
    r->header_chain->next = NULL;
    printf("ngx_http_live_play_respond_header header packet\n");
    ngx_chain_t               *cl;
    cl = r->s->connection->send_chain(r->s->connection, r->header_chain, 0);
    if (cl == NGX_CHAIN_ERROR)
        return NGX_ERROR;
    return NGX_OK;
}



static ngx_int_t 
ngx_http_live_paly_join(ngx_http_live_play_request_ctx_t *r)
{
    ngx_int_t rc = ngx_http_rtmp_live_play((void*)r);
    if (rc == NGX_STREAM_BACK_CC) {
         rc = ngx_http_get_relay_status((void*)r);
         if (rc == NGX_OK)
            return NGX_STREAM_BACK_CC;   
    }
    return rc;
}


/*
void
ngx_http_rtmp_live_socket(ngx_connection_t *c)
{
    struct sockaddr_in  *sin;
    sin = (struct sockaddr_in *)c->sockaddr;
    printf("ngx_http_rtmp_live_socket local_ip:%s time:%ld\n", inet_ntoa(sin->sin_addr), ngx_cached_time->msec);
}
*/

static void 
ngx_http_live_play_init_log(ngx_http_live_play_request_ctx_t *pr)
{
    ngx_http_request_t      *r;

    pr->log_type = 0;
    pr->request_ts = ngx_rtmp_live_current_msec();

    r = pr->s;

    struct sockaddr_in  *sin;
    sin = (struct sockaddr_in *)r->connection->sockaddr;
    char *client;
    client  = inet_ntoa(sin->sin_addr);

    // 获取client ip 
    pr->client_ip.len = ngx_strlen(client)+1;
    pr->client_ip.data = ngx_pcalloc(r->pool, pr->client_ip.len);
    ngx_memzero(pr->client_ip.data, pr->client_ip.len);
    ngx_memcpy(pr->client_ip.data, client, (size_t)ngx_strlen(client));
    // printf("ngx_http_rtmp_live_socket %ld client_ip:%s server_ip:%s\n", ngx_strlen(client), client, r->headers_in.server.data);


    // 获取server ip
    u_char      server[128];
    u_char      ch;
    ngx_uint_t   i = 0;
    ngx_memzero(server, 128);
    do {
        ch = r->headers_in.server.data[i];
        server[i] = ch;
        i++;

    } while (ch != ':' && ch != '\0');
    server[i-1] = '\0';

    pr->server_ip.len = i-1;
    pr->server_ip.data = ngx_pcalloc(r->pool, i);
    ngx_memzero(pr->server_ip.data, i);
    ngx_memcpy(pr->server_ip.data, server, pr->server_ip.len);

    // 获取host 
    // ngx_log_error(NGX_LOG_ERR, global_log, 0, "WOCAOCAO key:%s value:%s\n",r->headers_in.host->key.data, r->headers_in.host->value.data);
    pr->host.len = r->headers_in.host->value.len;
    pr->host.data = r->headers_in.host->value.data;

    // 获取 pull url
    i = 7 + pr->host.len + r->uri.len;
    pr->pull_url.len = i+1;
    pr->pull_url.data = ngx_pcalloc(r->pool, i+1);
    ngx_memzero(pr->pull_url.data , pr->pull_url.len);
    pr->pull_url.data[0] = 'h';
    pr->pull_url.data[1] = 't';
    pr->pull_url.data[2] = 't';
    pr->pull_url.data[3] = 'p';
    pr->pull_url.data[4] = ':';
    pr->pull_url.data[5] = '/';
    pr->pull_url.data[6] = '/';
    ngx_memcpy(pr->pull_url.data + 7, pr->host.data, pr->host.len);
    ngx_memcpy(pr->pull_url.data + 7 + pr->host.len, r->uri.data, r->uri.len);   
}
static ngx_int_t 
ngx_http_live_play_handler(ngx_http_request_t * r)
{
    ngx_http_live_play_request_ctx_t *pr;
    ngx_int_t  rc = 0;

    if(r == NULL && r->uri.len <= 4)
        return NGX_HTTP_BAD_REQUEST;

    if(r->method != NGX_HTTP_GET) // http mothod  not get  ,so request fail;
        return NGX_HTTP_BAD_REQUEST;
    
    //抛弃请求体
    if(ngx_http_discard_request_body(r) != NGX_OK)
        return NGX_HTTP_BAD_REQUEST;
    
    // 纯粹为了print  
    char str[1024] = {'\0'};
    char args[1024] = {'\0'};
    ngx_str_format_string(r->uri, str);
    ngx_str_format_string(r->args, args);
    printf("mothod %ld, uri %s, args %s\n",r->method,str,args);
    // print 
    
    pr = (ngx_http_live_play_request_ctx_t*)ngx_pcalloc(r->pool,sizeof(ngx_http_live_play_request_ctx_t));
    if (ngx_http_parse_play_uri(r->uri, pr) !=  NGX_OK) {
        ngx_http_live_play_close_request(r);
        return NGX_ERROR;
    }
    // printf("app:%s stream:%s suffix:%s\n", pr->app.data, pr->stream.data, pr->suffix.data);
    if (ngx_parse_args(r, pr) != NGX_OK) {
        ngx_http_live_play_close_request(r);
        return NGX_ERROR;
    }
    
    pr->header_chain = (ngx_chain_t*)ngx_pcalloc(r->pool,sizeof(ngx_chain_t));
    pr->s = r;
    pr->send_header_flag  = 0;

    // 初始化打印日志相关参数
    ngx_http_live_play_init_log(pr);
    
    
    // 纯粹为了打印
    char app[64] = {'\0'};
    char stream[256] = {'\0'};
    char param[1024] = {'\0'};
    char suffix[16] = {'\0'};
    ngx_str_format_string(pr->app,app);
    ngx_str_format_string(pr->stream,stream);
    ngx_str_format_string(pr->suffix,suffix);
    printf("app : %s stream : %s  param : %s suffix : %s\n",app,stream,param,suffix);
   

    ngx_http_set_ctx(r, pr, ngx_http_live_play_module);
    //r->keepalive = 0;
    
    // 鉴权
    if (ngx_http_live_authentication(pr) != NGX_OK) {
        ngx_http_live_play_respond_header(pr, HTTP_STATUS_403, "Video/x-flv", NULL); // 返回禁止拉流
        ngx_http_live_play_close_request(r);
        return NGX_HTTP_NOT_ALLOWED;
    } else {
        //查找流是否存在
        if ((rc = ngx_http_live_paly_join(pr)) != NGX_OK) { // 不允许加入则返回流找不到
            if (rc == NGX_STREAM_BACK_CC) { //等待回源 或者302跳转
                //启动定
                ngx_event_t *e = &pr->send_header_timeout_ev;
                if (!pr->send_header_timeout_ev.timer_set) {
                    ngx_http_live_play_loc_conf_t* hlplc = NULL;
                    hlplc = (ngx_http_live_play_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_live_play_module);
                    
                    e->data = r->connection;
                    e->log = r->connection->log;
                    e->handler = ngx_http_live_play_send_header_ev;
                    ngx_add_timer(e, hlplc->http_send_header_timeout);
                }
                printf("waiting stream back end\n");
            } else if (rc == NGX_STREAM_REWART) { //直接302 跳转
                  if (pr->relay_ctx->http_pull_url.len > 0){
                       char location[1024] = {'\0'};
                       ngx_str_format_string(pr->relay_ctx->http_pull_url,location);
                       ngx_http_live_play_respond_header(pr, HTTP_STATUS_302, "Video/x-flv", location);
                       ngx_http_live_play_close_request(r);
                       return NGX_OK;
                  } else{
                      ngx_http_live_play_respond_header(pr, HTTP_STATUS_404, "Video/x-flv", NULL);
                      ngx_http_live_play_close_request(r);
                      return NGX_HTTP_NOT_ALLOWED;
                  }
            } else {
                ngx_http_live_play_respond_header(pr, HTTP_STATUS_404, "Video/x-flv", NULL);
                ngx_http_live_play_close_request(r);
                return NGX_HTTP_NOT_ALLOWED;
            }
        } else {
            if (ngx_http_live_play_respond_header(pr, HTTP_STATUS_200, "Video/x-flv", NULL) == NGX_ERROR) {
                printf("send header error NGX_HTTP_NOT_ALLOWED\n");
		        return NGX_HTTP_NOT_ALLOWED;
            }
            pr->send_header_flag = 1;
        }
    }
    printf("process end\n");
    r->connection->read->handler = ngx_http_live_play_recv_handler;
    r->connection->data = r;
    r->connection->read->data =r->connection;
    r->rewrite_close = 1;
    return NGX_OK;
}


ngx_int_t 
ngx_http_live_send_message(ngx_http_live_play_request_ctx_t *pr, ngx_chain_t* out, 
        u_char mtype, unsigned int mlen, unsigned int pts, unsigned int delta)
{
    if(pr == NULL || out == NULL || mlen <= 0 || mtype > HTTP_FLV_VIDEO_KEY_FRAME_TAG)
        return NGX_ERROR;

    ngx_http_flv_frame_t *frame = alloc_http_flv_frame(pr);
    if (frame == NULL)
        return NGX_ERROR;

    frame->mtype = mtype; 
    frame->mlen = mlen;
    frame->mpts = pts;
    frame->mdelte = delta;
    frame->out = ngx_http_flv_copy_tag_mem(out);
    frame->next = NULL;

    if (pr->frame_chain_head == NULL) {
        pr->frame_chain_head = frame;
        pr->frame_chain_tail = pr->frame_chain_head;
    } else {
        pr->frame_chain_tail->next = frame;
        pr->frame_chain_tail = frame;
    }

    if (!pr->s->connection->write->active) {
        ngx_http_live_play_write_handler(pr->s->connection->write);
        printf("ngx_http_live_send_message  send data to net ----\n");
        /*return ngx_add_event(r->connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT);*/
    }
    
    // 打印日志
    ngx_http_request_t  *r = pr->s;
    char *szformat = NULL;
    // 获取日志唯一id
    u_char session[32] = {'\0'};

    ngx_sprintf(session, "%l_%d", pr->current_ts, r->connection->fd);
    if (pr->log_type == 0) { 
        szformat = "{_type:v2.edgePullStart,timestamp:%l,session:%s,clientIP:%V,serverIP:%V,host:%V,name:%V,protocolType:http-flv,responseTime:%l,pullUrl:%V}";
        ngx_log_error(NGX_LOG_ERR, global_log, 0, szformat, pr->current_ts, session, &pr->client_ip, &pr->server_ip, &pr->host, &pr->stream, pr->current_ts-pr->request_ts, &pr->pull_url);
        pr->log_type = 1;
    } else {
        if (mtype == HTTP_FLV_VIDEO_TAG) {
            pr->video_size += mlen;
        } else if (mtype == HTTP_FLV_AUDIO_TAG) {
            pr->audio_size += mlen;
        }
        pr->send_frame += 1;
         
        szformat = "{_type:v2.edgePullWatch,timestamp:%l,session:%s,clientIP:%V,serverIP:%V,host:%V,name:%V,protocolType:http-flv,pullUrl:%V,pts:%l,videoSize:%l,audioSize:%l,delay:%l,sendFrame:%l,dropVideoFrame:%l,cacheVideoFrame:%l}";
        ngx_log_error(NGX_LOG_ERR, global_log, 0, szformat, pr->current_ts, session, &pr->client_ip, &pr->server_ip, &pr->host, &pr->stream, &pr->pull_url, pts, pr->video_size, pr->audio_size, delta, pr->send_frame, pr->dropVideoFrame, pr->cacheVideoFrame);
    }
    return NGX_OK;
}

static void 
ngx_http_live_play_send_header_ev(ngx_event_t *ev)
{
    ngx_connection_t * c = (ngx_connection_t*)ev->data;
    ngx_http_request_t *r = (ngx_http_request_t*)c->data;
	ngx_http_live_play_request_ctx_t *  hctx = (ngx_http_live_play_request_ctx_t*)ngx_http_get_module_ctx(r,ngx_http_live_play_module);	
    if(c == NULL ||  r == NULL || hctx == NULL)
        return ;
    printf("send header timeout \n");

    ngx_http_live_play_close_request(r);
}

static ngx_int_t 
ngx_http_get_stream_status(ngx_http_live_play_request_ctx_t *hctx)
{
    return ngx_http_get_relay_status((void*)hctx);
}

ngx_int_t  
ngx_http_live_play_send_http_header(void* ptr)
{
    if (ptr == NULL)
        return NGX_ERROR;
    printf("ngx_http_live_play_send_http_header\n");
    ngx_http_live_play_request_ctx_t  *hctx = (ngx_http_live_play_request_ctx_t*)ptr;
    ngx_int_t rc = 0;
    char location[1024] = {'\0'};

    if (hctx->send_header_timeout_ev.timer_set) {
        ngx_del_timer(&hctx->send_header_timeout_ev);
    }

    if (hctx->send_header_flag == 1) //表示已经发送过头信息
        return NGX_OK;

    rc = ngx_http_get_stream_status((void*)hctx);

    ngx_http_respond_henader_status status = HTTP_STATUS_200;
    switch (rc) {
        case NGX_OK:
            status = HTTP_STATUS_200;
            break;
        case NGX_ERROR:
            status  = HTTP_STATUS_404;
            break;
        case NGX_STREAM_REWART: 
            {
                if (hctx->relay_ctx->http_pull_url.len > 0) {
                    ngx_str_format_string(hctx->relay_ctx->http_pull_url,location);
                    status = HTTP_STATUS_302;
                } else {
                    status = HTTP_STATUS_404;
                }
            }
            break;
    }
    
    if (ngx_http_live_play_respond_header(hctx, status, "Video/x-flv", location) == NGX_ERROR || 
            rc != NGX_OK ) {
        printf("send header error\n");
        ngx_http_live_play_close(hctx);
        return NGX_ERROR;
    }
    hctx->send_header_flag  = 1; 
    return NGX_OK;
}
