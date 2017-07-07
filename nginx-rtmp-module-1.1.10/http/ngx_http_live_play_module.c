#include "ngx_http_live_play_module.h"
#include "ngx_http_rtmp_live_module.h"
#include "ngx_rtmp_to_flv_packet.h"
#include "ngx_http_play_scheduler.h"
#include "ngx_rtmp_edge_log.h"

static char * ngx_http_live_play_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static void * ngx_http_live_play_create_srv_conf(ngx_conf_t * cf);
static void * ngx_http_live_play_create_loc_conf(ngx_conf_t * cf);
static char * ngx_http_live_play_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char * ngx_http_live_play_set(ngx_conf_t * cf,ngx_command_t * cmd,void* conf);
static char * ngx_http_live_play_set_domain(ngx_conf_t * cf,ngx_command_t * cmd,void* conf);

static ngx_int_t ngx_http_live_play_handler(ngx_http_request_t * r);

static void ngx_http_live_play_send_header_ev(ngx_event_t *ev);

static void ngx_http_live_play_send_data_timeout_ev(ngx_event_t *ev);

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

    {ngx_string("http_live_app"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_live_app), 
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
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_send_chunk_size),//default NGX_HTTP_PULL_KEEPALIVE_TIMEOUT
        NULL},

    {ngx_string("http_send_max_chunk_count"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_send_max_chunk_count),//default NGX_HTTP_PULL_KEEPALIVE_TIMEOUT
        NULL},

    { ngx_string("http_idle_play_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t, http_idle_timeout),
        NULL },

    {ngx_string("http_play_cache_on"),
        NGX_HTTP_LOC_CONF |NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_play_cache_on), 
        NULL },

    { ngx_string("http_play_cahce_time_duration"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t, http_play_cahce_time_duration),
        NULL },

    {ngx_string("http_play_cahce_frame_num"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,http_play_cahce_frame_num),//default NGX_HTTP_PULL_KEEPALIVE_TIMEOUT
        NULL},

         {ngx_string("cut_play_before_drop_num"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_loc_conf_t,cut_play_before_drop_num),//default NGX_HTTP_PULL_KEEPALIVE_TIMEOUT
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
    conf->http_idle_timeout = NGX_CONF_UNSET_MSEC;
    conf->http_play_cahce_frame_num = NGX_CONF_UNSET_UINT;
    conf->http_play_cahce_time_duration = NGX_CONF_UNSET_MSEC;
    conf->http_play_cache_on = NGX_CONF_UNSET;
    conf->cut_play_before_drop_num = NGX_CONF_UNSET_UINT;
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
    ngx_conf_merge_str_value(conf->http_live_app,prev->http_live_app,"");
    ngx_conf_merge_msec_value(conf->http_send_timeout, prev->http_send_timeout,5000); 
    ngx_conf_merge_msec_value(conf->http_send_header_timeout, prev->http_send_header_timeout,5000); 
    
    ngx_conf_merge_uint_value(conf->http_send_chunk_size,prev->http_send_chunk_size,4096);
    ngx_conf_merge_uint_value(conf->http_send_max_chunk_count,prev->http_send_max_chunk_count,256);
    ngx_conf_merge_msec_value(conf->http_idle_timeout, prev->http_idle_timeout, 0);

    ngx_conf_merge_value(conf->http_play_cache_on,prev->http_play_cache_on, 0);
    ngx_conf_merge_msec_value(conf->http_play_cahce_time_duration, prev->http_play_cahce_time_duration, 0);
    ngx_conf_merge_uint_value(conf->http_play_cahce_frame_num,prev->http_play_cahce_frame_num,1024);
    ngx_conf_merge_uint_value(conf->cut_play_before_drop_num,prev->cut_play_before_drop_num,10);
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
ngx_http_parse_play_uri(ngx_str_t uri, ngx_http_live_play_request_ctx_t *pr, ngx_http_request_t* r)
{
    if (pr == NULL)
        return NGX_ERROR;

    ngx_http_live_play_loc_conf_t* hlplc = NULL;
    hlplc = (ngx_http_live_play_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_live_play_module);

    char* p = (char*)uri.data;
    ngx_uint_t len = 0;
    if (*p != '/'){
        ngx_printf_log("ngx_http_live_play_module","ngx_http_parse_play_uri","url format error");
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

    if (hlplc->http_live_app.len > 0 && hlplc->http_live_app.data != NULL ) {
        pr->app = hlplc->http_live_app;
    }
    if(pr->stream.len <= 0 ||  pr->suffix.len <= 0)
        return NGX_ERROR;
    return NGX_OK;
}

static ngx_int_t 
ngx_parse_args(ngx_http_request_t* r,ngx_http_live_play_request_ctx_t* pr)
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

    if (pr->idle_evt.timer_set) {
        ngx_del_timer(&pr->idle_evt);
    }
    

    pr->current_ts = ngx_rtmp_live_current_msec();
    pr->status_code = r->status_code;
    ngx_rtmp_edge_log(NGX_EDGE_HTTP, NGX_EDGE_PULL_STOP, pr, pr->current_ts);
    

    //删除
    ngx_http_rtmp_live_close_play_stream((void*)pr);
    
    if (pr->frame_chain_head) {
        ngx_http_flv_frame_t *frame = pr->frame_chain_head;
        while (frame) {
            ngx_http_flv_free_tag_mem(frame->out);
            frame->out = NULL;
            if (pr->frame_chain_head) {
                frame = pr->frame_chain_head->next;
                if(frame)
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
    ngx_printf_log("ngx_http_live_play_module","ngx_http_live_play_close_request","close play");
    r->keepalive = 0;
	ngx_http_finalize_request(r,NGX_DONE);
    r->close_flag = 1;
}

static void 
ngx_http_live_play_close_session_handler(ngx_event_t *e)
{
    ngx_http_request_t *  r = e->data;
    if(r != NULL) {
        //r->status_code = ngx_unknown_close_err; 
        ngx_http_live_play_close_request(r);   
    }
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
    ngx_printf_log("ngx_http_live_play_module","ngx_http_live_play_close","add close event");

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
    ngx_printf_log("ngx_http_live_play_module","ngx_http_live_play_recv_handler","recv data");
    ngx_connection_t * c = (ngx_connection_t *)ev->data;  
    if (c== NULL)
        return;

    ngx_int_t n;

    u_char buf[1024] = {0};
    while (1) {
        n = c->recv(c, buf, sizeof(buf));
        if (n == NGX_ERROR || n == 0) {
            ev->error = 1;
            break;
        }

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                ev->error = 1;
                break;
            } else {
                return;
            }
        }
        if (n < 0)
            break;

        if(n > 0)//暂时不处理
            return ;
    }
    ngx_http_request_t *  r = (ngx_http_request_t * )c->data;

    if (n == 0){
        r->status_code = ngx_normal_close; 
    } else {
        r->status_code = ngx_http_live_recv_handler_err; 
    }
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
    if (c->destroyed){
        ev->error = 1;
        return;
    }
	if (ev->error != 0){
        r->status_code = ngx_http_live_write_handler_err; 
        ngx_http_live_play_close_request(r);
		return;
	}

    if (ev->timedout) {
        c->timedout = 1;
        r->status_code = ngx_http_live_client_timedout; 
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
                    printf("send full %ld\n",n);
                    if(n > 0 &&  n <= send_one_len)
                        frame->out->buf->pos += n;

                    frame->next = hctx->frame_chain_head;
                    hctx->frame_chain_head = frame;
                    
                    if(hctx->frame_chain_tail == NULL)
                       hctx->frame_chain_tail = hctx->frame_chain_head;
                    ngx_add_timer(c->write, hlplc->http_send_timeout);
                    ngx_printf_log("ngx_http_live_play_module","ngx_http_live_play_write_handler","ngx_handle_write_event");
                    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                        r->status_code = ngx_http_live_write_event_err; 
                        ngx_http_live_play_close_request(r);
                    }
                    return;
                } else {
                    
                    if (n < 0) {
                        r->status_code = ngx_http_live_send_data_err; 
                        ngx_http_live_play_close_request(r);
                        return;
                    }
                    hctx->current_send_count++;
                    frame->out->buf->pos += n;
                    send_len -= n;
                }
            }

            hctx->current_send_count = 0;
            if(frame->mtype >= HTTP_FLV_VIDEO_TAG)
            {
                hctx->cache_frame_num--;
                hctx->cache_time_duration -= frame->mdelte;
                hctx->video_pts = frame->mpts;
                hctx->recv_video_size += frame->mlen;
                if(hctx->first_tag && frame->mtype == HTTP_FLV_VIDEO_KEY_FRAME_TAG){
                    hctx->first_tag = 0;
                    hctx->system_first_pts = hctx->current_ts;
                    hctx->data_first_pts = frame->mpts;
                }
            }else{
                hctx->audio_pts = frame->mpts;
                hctx->recv_audio_size += frame->mlen;
            }
             hctx->recv_video_frame += 1;

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
    r->s->header_sent = 1;
    r->send_header_flag = 1;
    r->header_chain->next = NULL;
    ngx_printf_log("ngx_http_live_play_module","ngx_http_live_play_respond_header","send header");
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
    if (rc != NGX_ERROR) {
         ngx_int_t rewrite_rc = ngx_http_get_relay_status((void*)r);
         if (rewrite_rc != NGX_OK)
            rc = rewrite_rc;
    }
    return rc;
}

static void 
ngx_http_live_play_init_log(ngx_http_live_play_request_ctx_t *pr)
{
    ngx_http_request_t      *r;

    pr->log_type = 0;
    pr->request_ts = ngx_rtmp_live_current_msec();

    r = pr->s;
    r->status_code = ngx_unknown_close_err;
    
    // 获取日志唯一id
    ngx_memzero(pr->uuid, 32);
    ngx_sprintf(pr->uuid, "%l_%d", pr->request_ts, r->connection->fd);

    pr->server_ip.len = 0;
    pr->server_ip.data = NULL;

    pr->client_ip.len = 0; 
    pr->client_ip.data = NULL;
    
    pr->host.len = 0;
    pr->host.data = NULL;
    /*
    pr->name.len = 0;
    pr->name.data = NULL;
    */
    pr->pull_url.len = 0;
    pr->pull_url.data = NULL;

    // 获取client server ip
    struct sockaddr_in sa;
    int len = sizeof(sa);

    if (getsockname(r->connection->fd, (struct sockaddr *)&sa, (socklen_t *)&len) != 0) {
        return;
    }
    char *server_ip = inet_ntoa(sa.sin_addr);
    pr->server_ip.len = ngx_strlen(server_ip);
    pr->server_ip.data = ngx_pcalloc(r->connection->pool, pr->server_ip.len+1);
    ngx_memzero(pr->server_ip.data, pr->server_ip.len+1);
    ngx_memcpy(pr->server_ip.data, server_ip, pr->server_ip.len);
    
    
    if (getpeername(r->connection->fd, (struct sockaddr *)&sa, (socklen_t *)&len) != 0) {
        return;
    }
    char *peer_ip = inet_ntoa(sa.sin_addr);
    pr->client_ip.len = ngx_strlen(peer_ip);
    pr->client_ip.data = ngx_pcalloc(r->connection->pool, pr->client_ip.len+1);
    ngx_memzero(pr->client_ip.data, pr->client_ip.len+1);
    ngx_memcpy(pr->client_ip.data, peer_ip, pr->client_ip.len);
    
    // 获取host 
    pr->host.len = r->headers_in.host->value.len;
    pr->host.data = r->headers_in.host->value.data;
    
    // 获取 pull url
    int i = 7 + pr->host.len + r->uri.len;
    pr->pull_url.len = i;
    pr->pull_url.data = ngx_pcalloc(r->pool, i+1);
    ngx_memzero(pr->pull_url.data , i+1);
    // ngx_memset(pr->pull_url.data, '\0', i+1);
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
    // print 
    ngx_printf_log("ngx_http_live_play_module","ngx_http_live_play_handler","mothod %ld, uri %s, args %s",r->method,str,args);

    pr = (ngx_http_live_play_request_ctx_t*)ngx_pcalloc(r->pool,sizeof(ngx_http_live_play_request_ctx_t));
    if(pr == NULL)
        return NGX_ERROR;
        
    //clear memory
    memset(pr,0,sizeof(ngx_http_live_play_request_ctx_t));

    pr->s = r;
    pr->send_header_flag  = 0;
    pr->cache_time_duration = 0;
    pr->cache_max_duration = 0;
    pr->first_tag = 1;
    pr->system_first_pts = 0;
    pr->data_first_pts = 0;
    memset(pr->client_isp_name,0,1024);
    // 初始化打印日志相关参数
    ngx_http_live_play_init_log(pr);

    ngx_http_set_ctx(r,pr,ngx_http_live_play_module);

    if (ngx_http_parse_play_uri(r->uri, pr, r) !=  NGX_OK) {
        r->status_code = ngx_http_request_uri_err;
        ngx_http_live_play_close_request(r);
        return NGX_ERROR;
    }
    if (ngx_parse_args(r, pr) != NGX_OK) {
        r->status_code = ngx_http_request_param_err;
        ngx_http_live_play_close_request(r);
        return NGX_ERROR;
    }
    
    pr->header_chain = (ngx_chain_t*)ngx_pcalloc(r->pool,sizeof(ngx_chain_t));
    
    
    // 纯粹为了打印
    char app[64] = {'\0'};
    char stream[256] = {'\0'};
    //char param[1024] = {'\0'};
    char suffix[16] = {'\0'};
    ngx_str_format_string(pr->app,app);
    ngx_str_format_string(pr->stream,stream);
    ngx_str_format_string(pr->suffix,suffix);

    ngx_http_live_play_process_slot((u_char*)stream,strlen(stream));

    if(ngx_http_live_authentication(pr) != NGX_OK) //鉴权
    {
        ngx_http_live_play_respond_header(pr,HTTP_STATUS_403,"Video/x-flv",NULL); // 返回禁止拉流
        r->status_code = ngx_http_live_status_403_err; 
        ngx_http_live_play_close_request(r);
        return NGX_HTTP_NOT_ALLOWED;
    }else {
        //查找流是否存在
        if((rc = ngx_http_live_paly_join(pr)) != NGX_OK){ // 不允许加入则返回流找不到
            if(rc == NGX_STREAM_BACK_CC) {//等待回源 或者302跳转
                //启动定
                ngx_event_t *e = &pr->send_header_timeout_ev;
                ngx_http_live_play_loc_conf_t* hlplc = NULL;
                hlplc = (ngx_http_live_play_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_live_play_module);

                pr->send_header_ev_count = hlplc->http_send_header_timeout/1000 + 1;
                if (!pr->send_header_timeout_ev.timer_set) {
                    e->data = r->connection;
                    e->log = r->connection->log;
                    e->handler = ngx_http_live_play_send_header_ev;
                    ngx_add_timer(e, 1000);
                }
            }else if(rc == NGX_STREAM_REWART){ //直接302 跳转
                  if(pr->relay_ctx && pr->relay_ctx->http_pull_url.len > 0){
                       char location[1024] = {'\0'};
                       ngx_str_format_string(pr->relay_ctx->http_pull_url,location);
                       ngx_http_live_play_respond_header(pr,HTTP_STATUS_302,"Video/x-flv",location);
                       r->status_code = ngx_http_live_stream_rewait_err; 
                       ngx_http_live_play_close_request(r);
                       return NGX_OK;
                  }else{
                      ngx_http_live_play_respond_header(pr,HTTP_STATUS_404,"Video/x-flv",NULL);
                      r->status_code = ngx_http_live_not_allowed; 
                      ngx_http_live_play_close_request(r);
                      return NGX_HTTP_NOT_ALLOWED;
                  }
            }else{
                ngx_http_live_play_respond_header(pr,HTTP_STATUS_404,"Video/x-flv",NULL);
                r->status_code = ngx_http_live_not_allowed; 
                ngx_http_live_play_close_request(r);
                return NGX_HTTP_NOT_ALLOWED;
            }
        }else{
            if(ngx_http_live_play_respond_header(pr,HTTP_STATUS_200,"Video/x-flv",NULL) == NGX_ERROR)
            {
                r->status_code = ngx_http_send_http_header_error; 
                ngx_http_live_play_close_request(r);
		        return NGX_HTTP_NOT_ALLOWED;
            }
            pr->send_header_flag = 1;
        }
    }
    r->connection->read->handler = ngx_http_live_play_recv_handler;
    r->connection->data = r;
    r->connection->read->data =r->connection;
    r->rewrite_close = 1;
    return NGX_OK;
}

ngx_int_t ngx_http_paly_cache_process(ngx_http_live_play_request_ctx_t *s,u_char mtype)
{
    ngx_http_live_play_loc_conf_t* lacf = NULL;
    lacf = (ngx_http_live_play_loc_conf_t*)ngx_http_get_module_loc_conf(s->s, ngx_http_live_play_module);
    ngx_http_live_play_request_ctx_t* ctx =  s;
    if (!lacf->http_play_cache_on)
    {
        //缓存太高断链
        if ( ctx->cache_frame_num > (lacf->http_play_cahce_frame_num * 2))
        {
            ctx->status_code = ngx_http_cut_by_cache_full; 
            ngx_http_live_play_close((void*)ctx); 
            return NGX_ERROR;
        }
    }
    else
    {
        ngx_uint_t  drop_delay_num = (s->drop_count / 3 + 1) > 3 ? 3 : (s->drop_count / 3 + 1);
        ngx_uint_t cache_duration =  lacf->http_play_cahce_time_duration * drop_delay_num;
        ngx_uint_t cache_frame = lacf->http_play_cahce_frame_num * drop_delay_num;
       // printf("frame %ld %ld duration %ld %ld\n",ctx->cache_frame_num,cache_frame,ctx->cache_time_duration,cache_duration);
        if (ctx->cache_frame_num > cache_frame
                || (cache_duration > 0 && ctx->cache_time_duration > cache_duration))
        {
            if(mtype == HTTP_FLV_VIDEO_TAG) //普通帧丢弃
            {
                ctx->cache_droping = 1;//丢帧标记
                return NGX_ERROR;
            }

            if(ctx->cache_frame_num > (cache_frame * 3 / 2)
                    || (cache_duration > 0 && ctx->cache_time_duration > (cache_duration * 3 / 2)))
            {
                if(mtype >= HTTP_FLV_VIDEO_TAG) //关键帧和普通帧都丢弃
                {
                    ctx->cache_droping = 1; //丢帧标记
                    return NGX_ERROR;
                }

                if(ctx->cache_frame_num > (cache_frame *  2)
                        || (cache_frame > 0 && ctx->cache_time_duration > (cache_frame * 2)))
                {
                    if(mtype >= HTTP_FLV_AUDIO_TAG) //音视频全部丢丢弃
                    {
                        ctx->cache_droping = 1; //丢帧标记
                        return NGX_ERROR;
                    }
                }
            }
        }
        else
        {
            if(ctx->cache_droping == 1) //判定为丢帧
            {
                if(ctx->cache_frame_num > (cache_frame * 3 / 4)
                        || (cache_duration > 0 && ctx->cache_time_duration > (cache_duration*3 / 4)))
                {
                    if(mtype >= HTTP_FLV_VIDEO_TAG) //普通帧丢弃
                    {
                        ctx->cache_droping = 1;//丢帧标记
                        return NGX_ERROR;
                    }
                }
                else
                {
                    if(mtype ==  HTTP_FLV_VIDEO_KEY_FRAME_TAG)// 新关键帧后才开始不丢帧
                        ctx->cache_droping = 0;
                    else if(mtype == HTTP_FLV_VIDEO_TAG)
                    {
                        ctx->cache_droping = 1;//丢帧标记
                        return NGX_ERROR;   
                    }
                }
            }
            else
            {
                ctx->cache_droping = 0;
            }
        }
    }
    return NGX_OK;
}

ngx_int_t 
ngx_http_live_send_message(ngx_http_live_play_request_ctx_t *pr, ngx_chain_t* out
        ,u_char mtype,unsigned int mlen,unsigned int pts,unsigned int delta)
{
    if(pr == NULL || out == NULL || mlen <= 0 || mtype > HTTP_FLV_VIDEO_KEY_FRAME_TAG)
        return NGX_ERROR;
    
     ngx_http_live_play_loc_conf_t* lacf = NULL;
    lacf = (ngx_http_live_play_loc_conf_t*)ngx_http_get_module_loc_conf(pr->s, ngx_http_live_play_module);
        
    //如果连接上一定时间没有数据就断开链接
    if (pr->idle_evt.timer_set) {
       ngx_add_timer(&pr->idle_evt, lacf->http_idle_timeout);
    }

    // 打印日志
    //判断是否还能处理数据
    if(ngx_http_paly_cache_process(pr, mtype) !=  NGX_OK) {
        if(mtype >= HTTP_FLV_VIDEO_TAG) {
            pr->drop_vduration += delta;
            pr->drop_vframe_num++;
            pr->dropVideoFrame++; // 总的
            pr->drop_video_size += mlen;
        } else if (mtype == HTTP_FLV_AUDIO_TAG) {
            pr->drop_audio_size += mlen;
        }

        if (pr->start_caton == 0) {
            pr->drop_count++;
            if((ngx_uint_t)pr->drop_count > lacf->cut_play_before_drop_num) //卡顿10次则主动链接
            {
                pr->status_code = ngx_http_cut_play_by_drop;
                ngx_http_live_play_close(pr);
                return NGX_ERROR;
            }
            ngx_rtmp_edge_log(NGX_EDGE_HTTP, NGX_EDGE_BUFFER_START, pr, pr->current_ts);
            pr->start_caton = 1;
        }
        return NGX_ERROR;
    } else {
        if(mtype >= HTTP_FLV_VIDEO_TAG) {
            pr->cache_frame_num++;
            pr->cache_time_duration += delta;
            if(pr->cache_max_duration < pr->cache_time_duration && delta < 2000)
            {
                pr->cache_max_duration  = pr->cache_time_duration;
            }
            
            if (mtype == HTTP_FLV_VIDEO_TAG && pr->start_caton == 1) {
                ngx_rtmp_edge_log(NGX_EDGE_HTTP, NGX_EDGE_BUFFER_STOP, pr, pr->current_ts);     
                pr->drop_vduration = 0;
                pr->drop_vframe_num = 0;
                pr->drop_video_size = 0;
                pr->drop_audio_size = 0;
                pr->start_caton = 0;
            }
        }
    }

    ngx_http_flv_frame_t * frame =  alloc_http_flv_frame(pr);
    if(frame == NULL)
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
    }
    
    pr->stream_ts = pts;
    if (pr->current_ts-pr->log_lts >= global_poll) {
        if (pr->log_type == 0) { 
            ngx_rtmp_edge_log(NGX_EDGE_HTTP, NGX_EDGE_PULL_START, pr, pr->current_ts);
            pr->log_type = 1;
        } else {
            ngx_rtmp_edge_log(NGX_EDGE_HTTP, NGX_EDGE_PULL_WATCH, pr, pr->current_ts);
            pr->lrecv_video_size = pr->recv_video_size;
            pr->lrecv_audio_size = pr->recv_audio_size;
            pr->lrecv_video_frame = pr->recv_video_frame;
        }
        pr->log_lts = pr->current_ts;
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
    if(hctx->send_header_ev_count > 0)
    {
        hctx->send_header_ev_count--;
        ngx_int_t rc = ngx_http_get_relay_status((void*)hctx);
        if(rc == NGX_STREAM_REWART){
            if(hctx->relay_ctx && hctx->relay_ctx->http_pull_url.len > 0){
                char location[1024] = {'\0'};
                ngx_str_format_string(hctx->relay_ctx->http_pull_url,location);
                ngx_http_live_play_respond_header(hctx,HTTP_STATUS_302,"Video/x-flv",location);
                r->status_code = ngx_http_live_stream_rewait_err; 
                ngx_http_live_play_close_request(r);
            }
        }else{
            if(!ev->timer_set)
                ngx_add_timer(ev, 1000);
        }
    }
    else
    {
        if(hctx->relay_ctx && hctx->relay_ctx->http_pull_url.len > 0){
            char location[1024] = {'\0'};
            ngx_str_format_string(hctx->relay_ctx->http_pull_url,location);
            ngx_http_live_play_respond_header(hctx,HTTP_STATUS_302,"Video/x-flv",location);

            r->status_code = ngx_http_live_status_302_err; 
            ngx_http_live_play_close_request(r);
        }else{
            ngx_http_live_play_respond_header(hctx,HTTP_STATUS_404,"Video/x-flv",NULL);
            r->status_code = ngx_http_live_send_header_timedout; 
            ngx_http_live_play_close_request(r); 
        }
    }
}

static void 
ngx_http_live_play_send_data_timeout_ev(ngx_event_t *ev)
{
    ngx_connection_t * c = (ngx_connection_t*)ev->data;
    ngx_http_request_t *r = (ngx_http_request_t*)c->data;
	ngx_http_live_play_request_ctx_t *  hctx = (ngx_http_live_play_request_ctx_t*)ngx_http_get_module_ctx(r,ngx_http_live_play_module);	
    if(c == NULL ||  r == NULL || hctx == NULL)
        return ;
        
    r->status_code = ngx_http_live_send_data_timedout; 
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
    if(ptr == NULL)
        return NGX_ERROR;
    ngx_http_live_play_request_ctx_t *  hctx = (ngx_http_live_play_request_ctx_t*)ptr;
    ngx_int_t rc = 0;
    ngx_http_live_play_loc_conf_t* lacf = NULL;
    lacf = (ngx_http_live_play_loc_conf_t*)ngx_http_get_module_loc_conf(hctx->s, ngx_http_live_play_module);
    
    char location[1024] = {'\0'};

    if (hctx->send_header_timeout_ev.timer_set) {
        ngx_del_timer(&hctx->send_header_timeout_ev);
    }

    if (lacf->http_idle_timeout > 0) {
        ngx_event_t *e = &hctx->idle_evt;
        if (!hctx->idle_evt.timer_set) {
            e->data = hctx->s->connection;
            e->log = hctx->s->connection->log;
            e->handler = ngx_http_live_play_send_data_timeout_ev;
            ngx_add_timer(e, lacf->http_idle_timeout);
        }
    }

    if(hctx->send_header_flag == 1) //表示已经发送过头信息
        return NGX_OK;
    ngx_printf_log("ngx_http_live_play_module","ngx_http_live_play_send_http_header","send header");

    rc = ngx_http_get_stream_status((void*)hctx);

    ngx_http_respond_henader_status status = HTTP_STATUS_200;
    switch(rc) {
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
                    hctx->s->status_code = ngx_http_live_status_302_err;
                } else {
                    status = HTTP_STATUS_404;
                }
            }
            break;
    }
    if(ngx_http_live_play_respond_header(hctx,status,"Video/x-flv",location) == NGX_ERROR
            ||rc != NGX_OK )
    {
        hctx->status_code = ngx_http_send_http_header_error;
        ngx_http_live_play_close(hctx);
		return NGX_ERROR;
    }
    hctx->send_header_flag  = 1; 
    return NGX_OK;
}
