#include "ngx_http_live_play_relay_module.h"
#include "ngx_http_live_play_module.h"
#include "ngx_http_rtmp_relay.h"
#include <ngx_md5.h>
#include "ngx_rtmp_edge_log.h"

char *
ngx_http_live_get_str_data(ngx_str_t *str);

static void * ngx_http_live_play_relay_create_loc_conf(ngx_conf_t * cf);
static char * ngx_http_live_play_relay_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
ngx_str_t   ngx_http_live_notify_urlencoded =
            ngx_string("application/x-www-form-urlencoded");
static ngx_command_t  ngx_http_live_play_relay_commands[] = {
    { ngx_string("http_on_play"),
        NGX_HTTP_LOC_CONF |NGX_CONF_FLAG,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t,http_on_play), 
        NULL },

    { ngx_string("relay_secret_id"),
        NGX_HTTP_LOC_CONF |NGX_CONF_FLAG,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t,secret_id), 
        NULL},

    { ngx_string("relay_secret_key"),
        NGX_HTTP_LOC_CONF |NGX_CONF_FLAG,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t,secret_key), 
        NULL},

    {ngx_string("relay_md5_on"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t,relay_md5_on), 
        NULL},

    { ngx_string("notify_method"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t, method_name),
        NULL },

    { ngx_string("notify_relay_redirect"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t, relay_redirect),
        NULL },

    { ngx_string("rtmp_sever_port"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t, rtmp_server_port),
        NULL },

    { ngx_string("http_netcall_timeout"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t, http_on_play_timeout),
        NULL }, 

    { ngx_string("rtmp_back_source_addr_param_name"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t, rtmp_back_source_addr_param_name),
        NULL },

    { ngx_string("http_back_source_addr_param_name"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t, http_back_source_addr_param_name),
        NULL },

    { ngx_string("reconnect_count_before_302"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_http_live_play_relay_loc_conf_t, reconnect_count_before_302),
        NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_live_play_relay_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create server configuration */
    NULL,                                      /* merge server configuration */

    ngx_http_live_play_relay_create_loc_conf,       /* create location configuration */
    ngx_http_live_play_relay_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_live_play_relay_module = {
    NGX_MODULE_V1,
    &ngx_http_live_play_relay_module_ctx,         /* module context */
    ngx_http_live_play_relay_commands,            /* module directives */
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

static ngx_url_t *ngx_http_live_play_relay_notify_parse_url(ngx_pool_t *pool, ngx_str_t *url)
{
    ngx_url_t  *u;
    size_t      add;

    add = 0;
    u = ngx_pcalloc(pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NULL;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
    }

    u->url.len = url->len - add;
    u->url.data = url->data + add;
    u->default_port = 80;
    u->uri_part = 1;

    if (ngx_parse_url(pool, u) != NGX_OK) {
        return NULL;
    }
    return u;
}

static void *ngx_http_live_play_relay_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_live_play_relay_loc_conf_t     *nacf;

    nacf = ngx_pcalloc(cf->pool, sizeof(ngx_http_live_play_relay_loc_conf_t));
    if (nacf == NULL) {
        return NULL;
    }
    nacf->url = NGX_CONF_UNSET_PTR;
    nacf->http_on_play_timeout = NGX_CONF_UNSET_MSEC;
    nacf->relay_redirect = NGX_CONF_UNSET;
    nacf->relay_md5_on = NGX_CONF_UNSET;
    nacf->bufsize = NGX_CONF_UNSET_SIZE;
    nacf->log = &cf->cycle->new_log;
    nacf->free_ctx = NGX_CONF_UNSET_PTR;
    nacf->pool = NGX_CONF_UNSET_PTR;
    nacf->rtmp_server_port = NGX_CONF_UNSET_UINT;
    nacf->reconnect_count_before_302 = NGX_CONF_UNSET_UINT;
    return nacf;
}


static char *ngx_http_live_play_relay_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_live_play_relay_loc_conf_t *prev = parent;
    ngx_http_live_play_relay_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->http_on_play_timeout, prev->http_on_play_timeout,
                              3000);
    ngx_conf_merge_value(conf->relay_redirect, prev->relay_redirect, 0);
    ngx_conf_merge_value(conf->relay_md5_on, prev->relay_md5_on, 0);
    ngx_conf_merge_str_value(conf->method_name,prev->method_name,"get");
    ngx_conf_merge_str_value(conf->secret_id,prev->secret_id,"");
    ngx_conf_merge_str_value(conf->http_on_play,prev->http_on_play,"");
    ngx_conf_merge_size_value(conf->bufsize, prev->bufsize, 4098);
    ngx_conf_merge_uint_value(conf->rtmp_server_port,prev->rtmp_server_port,1935);
    ngx_conf_merge_size_value(conf->bufsize, prev->bufsize, 4098);
    ngx_conf_merge_uint_value(conf->reconnect_count_before_302,prev->reconnect_count_before_302,3);
    ngx_conf_merge_str_value(conf->http_back_source_addr_param_name,prev->http_back_source_addr_param_name,"http_source");
    ngx_conf_merge_str_value(conf->rtmp_back_source_addr_param_name,prev->rtmp_back_source_addr_param_name,"rtmp_source");
    if (conf->http_on_play.len > 0) {
        prev->active = conf->active = 1;
        conf->url = ngx_http_live_play_relay_notify_parse_url(cf->pool,&conf->http_on_play);
    }
    
    ngx_conf_merge_ptr_value(conf->url, prev->url, NULL);

    conf->pool = ngx_create_pool(4096, cf->log);
    conf->free_ctx = NULL;
    if (conf->pool == NULL) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static ngx_http_live_play_relay_ctx_t*  ngx_http_live_relay_alloc_ctx(ngx_http_live_play_relay_loc_conf_t* loc)
{
    ngx_http_live_play_relay_ctx_t * ctx = NULL;
    if(loc)
    {
        if(loc->free_ctx)
        {
            ctx = loc->free_ctx;
            loc->free_ctx = ctx->next;
        }
        else
        {
            if(loc->pool)
            {
                ctx = (ngx_http_live_play_relay_ctx_t*)ngx_pcalloc(loc->pool,sizeof(ngx_http_live_play_relay_ctx_t));
                memset(ctx, 0, sizeof(ngx_http_live_play_relay_ctx_t));
            }
        }
    }
    if(ctx)
    {
        ctx->url_len = loc->bufsize; 
        if(ctx->pool == NULL)
            ctx->pool = ngx_create_pool(4096, loc->log);
        if(ctx->pool)
        {
            ctx->http_pull_url.data = (u_char*)ngx_pcalloc(ctx->pool,ctx->url_len);
            ctx->http_pull_url.len = 0;

            ctx->rtmp_pull_url.data = (u_char*)ngx_pcalloc(ctx->pool,ctx->url_len);
            ctx->rtmp_pull_url.len = 0;
        }
        ctx->next = NULL;
    }
    return ctx;
}

static void ngx_http_live_play_relay_free_ctx(ngx_http_live_play_relay_ctx_t*ctx,ngx_http_live_play_relay_loc_conf_t* loc)
{
    if(ctx && loc)
    {
       if(ctx->pool)
       {
           ngx_destroy_pool(ctx->pool);
       } 
        memset(ctx, 0, sizeof(ngx_http_live_play_relay_ctx_t));
        ctx->next = loc->free_ctx ;
        loc->free_ctx = ctx;
        ctx->pool = NULL;
    }
}

static ngx_int_t ngx_http_live_netcall_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_live_netcall_session_t   *cs = data;

    pc->sockaddr =(struct sockaddr *)&cs->url->sockaddr;
    pc->socklen = cs->url->socklen;
    pc->name = &cs->url->host;

    return NGX_OK;
}


static void ngx_http_live_netcall_free_peer(ngx_peer_connection_t *pc, void *data,
            ngx_uint_t state)
{
}

static void 
ngx_http_live_netcall_close(ngx_connection_t *cc)
{
    ngx_http_live_netcall_session_t         *cs;
    ngx_pool_t                         *pool;
    ngx_buf_t                          *b;
    ngx_http_live_play_relay_ctx_t     *ctx = NULL;

    cs = cc->data;

    if (cc->destroyed) {
        return;
    }

    if (cc->read->timer_set) {
        ngx_del_timer(cc->read);
    }

    if (cc->write->timer_set) {
        ngx_del_timer(cc->write);
    }

    cc->destroyed = 1;
    ctx = cs->ctx;
    //liw to do
    if (!cs->detached) {
        if (cs->in && cs->sink) {
            cs->sink(ctx, cs->in);

            b = cs->in->buf;
            b->pos = b->last = b->start;
        }

        if (cs->handle && cs->handle(ctx, cs->arg, cs->in) != NGX_OK) {
            //ngx_rtmp_finalize_session(s);
        }
    }
    
    // global_log
    ngx_uint_t  current_ts = ngx_rtmp_current_msec();
    if (ctx != NULL) {
        ngx_rtmp_edge_log(NGX_EDGE_HTTP, NGX_EDGE_BACK_SOURCE, cs, current_ts);
    }
    
    pool = cc->pool;
    ngx_close_connection(cc);
    ngx_destroy_pool(pool);
     ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_netcall_close","close");
}


static void ngx_http_live_netcall_recv(ngx_event_t *rev)
{
    ngx_http_live_netcall_session_t         *cs;
    ngx_connection_t                   *cc;
    ngx_chain_t                        *cl;
    ngx_int_t                           n;
    ngx_buf_t                          *b;

    cc = rev->data;
    cs = cc->data;

    if (cc->destroyed) {
        return;
    }

    if (rev->timedout) {
        cc->timedout = 1;
        cs->status_code = ngx_http_relay_netcall_timedout;
        ngx_http_live_netcall_close(cc);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    for ( ;; ) {

        if (cs->inlast == NULL ||
            cs->inlast->buf->last == cs->inlast->buf->end)
        {
            if (cs->in && cs->sink) {
                if (!cs->detached) {
                    if (cs->sink(cs->ctx, cs->in) != NGX_OK) {
                        cs->status_code = ngx_http_relay_sink_err;
                        ngx_http_live_netcall_close(cc);
                        return;
                    }
                }

                b = cs->in->buf;
                b->pos = b->last = b->start;

            } else {
                cl = ngx_alloc_chain_link(cc->pool);
                if (cl == NULL) {
                    cs->status_code = ngx_http_relay_alloc_chain_err;
                    ngx_http_live_netcall_close(cc);
                    return;
                }

                cl->next = NULL;

                cl->buf = ngx_create_temp_buf(cc->pool, cs->bufsize);
                if (cl->buf == NULL) {
                    cs->status_code = ngx_http_relay_create_buf_err;
                    ngx_http_live_netcall_close(cc);
                    return;
                }

                if (cs->in == NULL) {
                    cs->in = cl;
                } else {
                    cs->inlast->next = cl;
                }

                cs->inlast = cl;
            }
        }

        b = cs->inlast->buf;

        n = cc->recv(cc, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            if (n == 0 ){
                cs->status_code = ngx_normal_close;
            } else {
                cs->status_code = ngx_http_relay_recv_data_err;
            }
            
            ngx_http_live_netcall_close(cc);
            return;
        }

        if (n == NGX_AGAIN) {
            if (cs->filter && cs->in
                && cs->filter(cs->in) != NGX_AGAIN)
            {
                cs->status_code = ngx_http_relay_recv_filter_err;
                ngx_http_live_netcall_close(cc);
                return;
            }

            ngx_add_timer(rev, cs->timeout);
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                cs->status_code = ngx_http_relay_read_event_err;
                ngx_http_live_netcall_close(cc);
            }
            return;
        }

        b->last += n;
    }
}


static void ngx_http_live_netcall_send(ngx_event_t *wev)
{
    ngx_http_live_netcall_session_t         *cs;
    ngx_connection_t                   *cc;
    ngx_chain_t                        *cl;

    cc = wev->data;
    cs = cc->data;

    if (cc->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, cc->log, NGX_ETIMEDOUT,
                "netcall: client send timed out");
        cc->timedout = 1;
        cs->status_code = ngx_http_relay_send_timedout;
        ngx_http_live_netcall_close(cc);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    cl = cc->send_chain(cc, cs->out, 0);

    if (cl == NGX_CHAIN_ERROR) {
        cs->status_code = ngx_http_relay_send_chain_err;
        ngx_http_live_netcall_close(cc);
        return;
    }

    cs->out = cl;

    /* more data to send? */
    if (cl) {
        ngx_add_timer(wev, cs->timeout);
        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            cs->status_code = ngx_http_relay_send_write_err;
            ngx_http_live_netcall_close(cc);
        }
        return;
    }

    /* we've sent everything we had.
     * now receive reply */
    ngx_del_event(wev, NGX_WRITE_EVENT, 0);

    ngx_http_live_netcall_recv(cc->read);
}

ngx_int_t ngx_http_live_md5(char * v,char *id,long ltime,char*random,char* szkey)
{
    char szmd5[4096]= {0};
    unsigned char md5_output[32];
    sprintf(szmd5,"%s.%s.%ld.%s",random,szkey,ltime,id);	
    MD5((unsigned char *)szmd5,strlen(szmd5),md5_output);
    int  mn = 0;
    char * pstr = v;
    for(; mn < 16;++mn)
    {
        snprintf(pstr,3,"%2.2x",md5_output[mn]);
        pstr += 2;
    }
    return NGX_OK;
}

void ngx_http_live_random_str(char* random,int n)
{
    char metachar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    srand(time(NULL));
    int i = 0;
    for (; i < n - 1; i++) {
        random[i] = metachar[rand() % 62];
    }
    random[n - 1] = '\0';
}

long ngx_http_live_currrent_time()
{
	struct timeval  time;     
	gettimeofday(&time,NULL);
	return time.tv_sec; 
}

ngx_int_t ngx_http_live_netclall_param(ngx_http_live_play_request_ctx_t * rc,char * args)
{
    if(args == NULL)
        return NGX_OK;
    char szid[256] = {'\0'};
    char szkey[256] = {'\0'};
    char szrandom[128] = {'\0'};
    long ltime = 0;
    char szsig[256] = {'\0'};
    char stream[256] = {'\0'};
    ngx_http_live_play_relay_loc_conf_t* hrlc;
    hrlc = (ngx_http_live_play_relay_loc_conf_t*)ngx_http_get_module_loc_conf(rc->s,ngx_http_live_play_relay_module);
    ngx_str_format_string(rc->stream,stream);
    ngx_http_live_random_str(szrandom,32);
    ltime = ngx_http_live_currrent_time();

    ngx_escape_uri((u_char*)szid,hrlc->secret_id.data,hrlc->secret_id.len,NGX_ESCAPE_ARGS);
    ngx_escape_uri((u_char*)szkey,hrlc->secret_key.data,hrlc->secret_key.len,NGX_ESCAPE_ARGS);
    ngx_http_live_md5(szsig,szid,ltime,szrandom,szkey);
    sprintf(args,"secretid=%s&time=%ld&random=%s&sign=%s&streamid=%s",szid,ltime,szrandom,szsig,stream);
    ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_netclall_param","args:%s",args);
    return NGX_OK;
}

ngx_chain_t * ngx_http_live_netcall_http_format_request(ngx_int_t method, ngx_str_t *host,
                                     ngx_str_t *uri, ngx_chain_t *args,
                                     ngx_chain_t *body, ngx_pool_t *pool,
                                     ngx_str_t *content_type)
{
    ngx_chain_t                    *al, *bl, *ret;
    ngx_buf_t                      *b;
    size_t                          content_length;
    static const char              *methods[2] = { "GET","POST" };
    static const char               rq_tmpl[] = " HTTP/1.0\r\n"
                                                "Host: %V\r\n"
                                                "Content-Type: %V\r\n"
                                                "Connection: Close\r\n"
                                                "Content-Length: %uz\r\n"
                                                "\r\n";

    content_length = 0;
    for (al = body; al; al = al->next) {
        b = al->buf;
        content_length += (b->last - b->pos);
    }

    /* create first buffer */

    al = ngx_alloc_chain_link(pool);
    if (al == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool, sizeof("POST") + /* longest method + 1 */
                                  uri->len);
    if (b == NULL) {
        return NULL;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last, "%s %V",
                           methods[method], uri);

    al->buf = b;

    ret = al;

    if (args) {
        *b->last++ = '?';
        al->next = args;
        for (al = args; al->next; al = al->next);
    }

    /* create second buffer */

    bl = ngx_alloc_chain_link(pool);
    if (bl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool, sizeof(rq_tmpl) + host->len +
                            content_type->len + NGX_SIZE_T_LEN);
    if (b == NULL) {
        return NULL;
    }

    bl->buf = b;

    b->last = ngx_snprintf(b->last, b->end - b->last, rq_tmpl,
                           host, content_type, content_length);

    al->next = bl;
    bl->next = body;

    return ret;
}

static ngx_chain_t *ngx_http_live_notify_create_request(ngx_http_request_t *s, ngx_pool_t *pool, ngx_chain_t *args)
{
    ngx_http_live_play_relay_loc_conf_t *nacf;
    ngx_chain_t                *al, *bl, *cl;
    ngx_url_t                  *url;
    ngx_int_t method = 0;

    nacf = ngx_http_get_module_loc_conf(s, ngx_http_live_play_relay_module);

    url = nacf->url;

    al = args;

    bl = NULL;
   
    if (strncmp((char*)nacf->method_name.data,"POST",strlen("POST")) == 0) {
        cl = al;
        al = bl;
        bl = cl;
        method = 1;
    }

    return ngx_http_live_netcall_http_format_request(method, &url->host,
                                                &url->uri, al, bl, pool,
                                                &ngx_http_live_notify_urlencoded);
}

static ngx_chain_t *ngx_http_live_notify_play_create(ngx_http_request_t *s, void *arg,ngx_pool_t *pool)
{
    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    size_t                         args_len;

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }
    char * v = (char*)arg;
    args_len = strlen(v);
    ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_notify_play_create","args:%s",v);
    b = ngx_create_temp_buf(pool,NGX_INT32_LEN * 3 + 1 + args_len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;
    if (args_len) {
//        b->last = (u_char*) ngx_escape_uri(b->last, (u_char*)v, args_len,NGX_ESCAPE_ARGS);
        b->last = (u_char *) ngx_cpymem(b->last, (u_char*)v, args_len);
        char args[2048] = {'\0'};
        strncpy(args,(char*)b->pos,args_len);
    }
    return ngx_http_live_notify_create_request(s, pool, pl);
} 

static ngx_int_t ngx_http_live_notify_parse_http_retcode(ngx_chain_t *in)
{
    ngx_buf_t      *b;
    ngx_int_t       n;
    u_char          c;

    /* find 10th character */
    n = 9;
    while (in) {
        b = in->buf;
        if (b->last - b->pos > n) {
            c = b->pos[n];
            if (c >= (u_char)'0' && c <= (u_char)'9') {
                switch (c) {
                    case (u_char) '2':
                        return NGX_OK;
                    case (u_char) '3':
                        return NGX_AGAIN;
                    default:
                        return NGX_ERROR;
                }
            }

            return NGX_ERROR;
        }
        n -= (b->last - b->pos);
        in = in->next;
    }

    return NGX_ERROR;
}

ngx_chain_t * ngx_http_live_netcall_http_skip_header(ngx_chain_t *in)
{
    ngx_buf_t       *b;

    /* find \n[\r]\n */
    enum {
        normal,
        lf,
        lfcr
    } state = normal;

    if (in == NULL) {
        return NULL;
    }

    b = in->buf;

    for ( ;; ) {

        while (b->pos == b->last) {
            in = in->next;
            if (in == NULL) {
                return NULL;
            }
            b = in->buf;
        }

        switch (*b->pos++) {
            case '\r':
                state = (state == lf) ? lfcr : normal;
                break;

            case '\n':
                if (state != normal) {
                    return in;
                }
                state = lf;
                break;

           default:
                state = normal;
        }
    }
}

static ngx_int_t 
ngx_http_live_notify_parse_http_message(ngx_http_live_play_relay_ctx_t *hrctx,ngx_chain_t *in)
{
    char data[4096] = {'\0'};
    in = ngx_http_live_netcall_http_skip_header(in);
    if (in) {
        int len = 0;
        char * ptr = data;
        while(in)
        {
            char* p = (char*)in->buf->pos;
            int l = in->buf->last - in->buf->pos;
            if(len + l > 4096)
                return NGX_ERROR;

            memcpy(ptr,p,l);
            ptr += l;
            len += l;
            in = in->next;
        }
        ptr[len+1] = '\0';

        char rtmp[2048] = {'\0'};
        char http[2048] = {'\0'};
        char* rtmp_url = "\"rtmp_pull_url\":";
        char*  http_url = "\"http_pull_url\":";
        int le = strlen(rtmp_url);
        char * ptr1 = strstr(data,rtmp_url);
        u_char* pt = NULL;
        if(ptr1)
        {

            ptr1 += le;
            pt = hrctx->rtmp_pull_url.data;
            if(*ptr1 == '\"' && pt)
            {
                ptr1++;
                int i = 0;
                while(ptr1 && *ptr1 != '\0')
                {
                    if(*ptr1 == '\"')
                        break;
                    if(*ptr1 != '\\')
                        pt[i++] = *ptr1;
                    ptr1++;
                }
                hrctx->rtmp_pull_url.len = i;
                ngx_str_format_string(hrctx->rtmp_pull_url,rtmp);
                ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_notify_parse_http_message","url :%s",rtmp);         
            }
        }

        char * ptr2 = strstr(data,http_url) ;
        if(ptr2 == NULL)
            return NGX_ERROR;

        ptr2 += le;
        pt = hrctx->http_pull_url.data;
        if(*ptr2 == '\"' && pt)
        {
            ptr2++;
            int i = 0;
            while(ptr2 && *ptr2 != '\0')
             {
                if(*ptr2 == '\"')
                    break;
                if(*ptr2 != '\\')
                    pt[i++] = *ptr2;
                ptr2++;
            }
            hrctx->http_pull_url.len = i;
            
            ngx_str_format_string(hrctx->http_pull_url,http);
            ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_notify_parse_http_message","url :%s",http);
        }
    }
    else
    {
        ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_notify_parse_http_message","data:error");
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_live_notify_play_handle(ngx_http_live_play_relay_ctx_t *hrctx,void *arg, ngx_chain_t *in)
{

    ngx_int_t rc;
    ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_notify_play_handle","begin");
    if(hrctx == NULL)
        return NGX_ERROR;
    // 删除定时器 
    ngx_event_t *ev = &hrctx->netcall_timeout_ev;
    if(ev->timer_set){
        ngx_del_timer(ev);
    }
    hrctx->cs = NULL;
    hrctx->backing = 0;

    //free
    /*char *message = (char*)malloc(1024 * 64);
    int len = 0;
    char * ptr = message;
    ngx_chain_t* cn = in;
    while(cn)
    {
        char* p = (char*)in->buf->pos;
        int l = in->buf->last - in->buf->pos;
        memcpy(ptr,p,l);
        ptr += l;
        len += l;
        cn = cn->next;
    }
    ptr[len+1] = '\0';
    printf("message len %d  body: %s \n",len,message);
    */

    rc = ngx_http_live_notify_parse_http_retcode(in);
    if (rc != NGX_OK) {
        hrctx->errcount++;
        ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_notify_play_handle","code error %ld",rc);
        return NGX_ERROR;
    }

    ngx_http_live_notify_parse_http_message(hrctx,in);
    
    if(hrctx->rtmp_pull_url.len < strlen("rtmp:\\"))
    {
        hrctx->errcount++;
        ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_notify_play_handle","rtmp url error");
        return NGX_ERROR;
    }

    return ngx_http_trigger_rtmp_relay_pull((void*)hrctx);
}

static void ngx_http_live_netcall_timeout(ngx_event_t *ev)
{
    ngx_http_live_play_relay_ctx_t* ctx = (ngx_http_live_play_relay_ctx_t*)ev->data;
    ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_netcall_timeout","netcall timeout");
    if(ctx)
    {
        if( ctx->cs && ctx->cs->pc )
        {
            ctx->cs->detached = 1;
            ctx->cs->status_code = ngx_http_relay_netcall_timedout;
            ngx_http_live_netcall_close(ctx->cs->pc->connection); 
            
        }
        ctx->cs = NULL;
        ctx->backing = 0;
    }
}

ngx_int_t ngx_http_live_netcall_create(ngx_http_live_play_request_ctx_t *rs, ngx_http_live_netcall_init_t *ci)
{
    
    ngx_http_live_play_relay_ctx_t* ctx;
    ngx_peer_connection_t          *pc;
    ngx_http_live_netcall_session_t     *cs;
    ngx_http_live_play_relay_loc_conf_t    *nhcf;
    ngx_connection_t               *c, *cc;
    ngx_pool_t                     *pool;
    ngx_int_t                       rc;

    nhcf = (ngx_http_live_play_relay_loc_conf_t*)ngx_http_get_module_loc_conf(rs->s,ngx_http_live_play_relay_module);

    pool = NULL;
    c = rs->s->connection;

    /* get module context */
    ctx = rs->relay_ctx;

    /* Create netcall pool, connection, session.
     * Note we use shared (app-wide) log because
     * s->connection->log might be unavailable
     * in detached netcall when it's being closed */
    pool = ngx_create_pool(4096, nhcf->log);
    if (pool == NULL) {
        goto error;
    }

    pc = ngx_pcalloc(pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL) {
        goto error;
    }

    cs = ngx_pcalloc(pool, sizeof(ngx_http_live_netcall_session_t));
    if (cs == NULL) {
        goto error;
    }
    cs->netcall_ts = ngx_rtmp_current_msec();

    /* copy arg to connection pool */
    if (ci->argsize) {
        cs->arg = ngx_pcalloc(pool, ci->argsize);
        if (cs->arg == NULL) {
            goto error;
        }
        ngx_memcpy(cs->arg, ci->arg, ci->argsize);
    }

    cs->timeout = nhcf->http_on_play_timeout;
    cs->bufsize = nhcf->bufsize;
    cs->url = ci->url;
    cs->ctx = rs->relay_ctx;
    cs->filter = ci->filter;
    cs->sink = ci->sink;
    cs->handle = ci->handle;
    if (cs->handle == NULL) {
        cs->detached = 1;
    }

    pc->log = nhcf->log;
    pc->get = ngx_http_live_netcall_get_peer;
    pc->free = ngx_http_live_netcall_free_peer;
    pc->data = cs;

    /* connect */
    rc = ngx_event_connect_peer(pc);
    if (rc != NGX_OK && rc != NGX_AGAIN ) {
        goto error;
    }

    cc = pc->connection;
    cc->data = cs;
    cc->pool = pool;
    cs->pc = pc;

    cs->out = ci->create(rs->s, ci->arg, pool);
    if (cs->out == NULL) {
        ngx_close_connection(pc->connection);
        goto error;
    }

    cc->write->handler = ngx_http_live_netcall_send;
    cc->read->handler = ngx_http_live_netcall_recv;

    if(!rs->relay_ctx->netcall_timeout_ev.timer_set)
    {
        rs->relay_ctx->netcall_timeout_ev.handler = ngx_http_live_netcall_timeout;
        rs->relay_ctx->netcall_timeout_ev.log = pc->log;
        rs->relay_ctx->netcall_timeout_ev.data = (void*)rs->relay_ctx;
        ngx_add_timer(&rs->relay_ctx->netcall_timeout_ev,nhcf->http_on_play_timeout);
    }
    
    ngx_http_live_netcall_send(cc->write);

    rs->relay_ctx->cs =  cs;

    return c->destroyed ? NGX_ERROR : NGX_OK;

error:
    if (pool) {
        ngx_destroy_pool(pool);
    }

    return NGX_ERROR;
}

ngx_int_t ngx_parse_args_list_have_source_addr(ngx_http_live_play_request_ctx_t * hctx)
{
    if(hctx == NULL)
        return NGX_ERROR;
    ngx_http_live_play_relay_loc_conf_t* hrlc;
    hrlc = (ngx_http_live_play_relay_loc_conf_t*)ngx_http_get_module_loc_conf(hctx->s,ngx_http_live_play_relay_module);
    
    if(hctx->param_list_head == NULL ||  hrlc == NULL ||  hctx->relay_ctx == NULL) 
        return NGX_ERROR;

    ngx_str_map_list_t *node = hctx->param_list_head;
    while(node)
    {
        ngx_str_map_node_t * args = node->node;
        if(args)
        {
            if(hrlc->rtmp_back_source_addr_param_name.len == args->key.len
            &&strncmp((char*)hrlc->rtmp_back_source_addr_param_name.data,(char*)args->key.data,args->key.len) == 0)
            {  
                memcpy(hctx->relay_ctx->rtmp_pull_url.data,args->value.data,args->value.len);
                hctx->relay_ctx->rtmp_pull_url.len = args->value.len;
            }

            if(hrlc->http_back_source_addr_param_name.len == args->key.len
            &&strncmp((char*)hrlc->http_back_source_addr_param_name.data,(char*)args->key.data,args->key.len) == 0)
            {
                memcpy(hctx->relay_ctx->http_pull_url.data,args->value.data,args->value.len);
                hctx->relay_ctx->http_pull_url.len = args->value.len;
            }
        }
        node = node->next;
    }
    if(hctx->relay_ctx->rtmp_pull_url.len <= 7)
        return NGX_ERROR;
    return NGX_OK;
}

static ngx_int_t  ngx_http_live_relay_copy_param(ngx_http_live_play_request_ctx_t * rc)
{
    ngx_http_live_play_relay_ctx_t * relay_ctx = rc->relay_ctx;
    if(relay_ctx == NULL)
        return NGX_ERROR;

    if(relay_ctx->app.len < rc->app.len)
    {
        relay_ctx->app.data = (u_char*)ngx_pcalloc(relay_ctx->pool,rc->app.len);
        if(relay_ctx->app.data  == NULL)
            return NGX_ERROR;
    }

    memcpy(relay_ctx->app.data,rc->app.data,rc->app.len);
    relay_ctx->app.len = rc->app.len;
    if(relay_ctx->stream.len < rc->stream.len)
    {
        relay_ctx->stream.data = (u_char*)ngx_pcalloc(relay_ctx->pool,rc->stream.len);
        if(relay_ctx->stream.data == NULL)
            return NGX_ERROR;
    }
    memcpy(relay_ctx->stream.data,rc->stream.data,rc->stream.len);
    relay_ctx->stream.len = rc->stream.len;
    return NGX_OK;
}

ngx_int_t ngx_http_live_relay_on_play(void * ptr)
{
    ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_relay_on_play","begin");
    ngx_http_live_netcall_init_t ci;
    ngx_http_live_play_request_ctx_t * rc = (ngx_http_live_play_request_ctx_t*)ptr;
    if(rc == NULL)
        return NGX_ERROR;
    
    ngx_http_live_play_relay_loc_conf_t* hrlc;
    hrlc = (ngx_http_live_play_relay_loc_conf_t*)ngx_http_get_module_loc_conf(rc->s,ngx_http_live_play_relay_module);
    if(hrlc == NULL || !hrlc->active || hrlc->http_on_play.len <= 4)
        return NGX_ERROR;
    
    if(rc->relay_ctx == NULL){
        ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_relay_on_play","create relay ctx");
        rc->relay_ctx = ngx_http_live_relay_alloc_ctx(hrlc);
    }
    if(rc->relay_ctx == NULL)
        return NGX_ERROR;

    rc->relay_ctx->relay_conf = hrlc;

    if(ngx_http_live_relay_copy_param(rc) == NGX_ERROR)
        return NGX_ERROR;

    ngx_http_set_ctx(rc->s, rc->relay_ctx, ngx_http_live_play_relay_module);
    if(ngx_parse_args_list_have_source_addr(rc) == NGX_OK) //判断参数中是否有回源地址,如果有就不需要再调用接口获取回源地址
    {
        ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_relay_on_play","ngx_parse_args_list_have_source_addr");
        return ngx_http_trigger_rtmp_relay_pull((void*)rc->s);
    }
    else
    {
        // rc->relay_ctx->refcount++;
        ngx_memzero(&ci, sizeof(ci));
        char v[1024*4] = {'\0'};
        ngx_http_live_netclall_param(rc,v);

        ci.url = hrlc->url;
        ci.create = ngx_http_live_notify_play_create;
        ci.handle = ngx_http_live_notify_play_handle;
        ci.arg = (void*)v;
        ci.argsize = strlen(v)+1;

        ngx_int_t rss = ngx_http_live_netcall_create(rc, &ci);
        if(rss ==  NGX_OK)
            rc->relay_ctx->backing = 1;
        return rss;
    }
}

ngx_int_t ngx_http_live_relay_on_play_close(void * ptr)
{
    ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_relay_on_play_close","begin");
    ngx_http_live_play_relay_ctx_t * relay_ctx = (ngx_http_live_play_relay_ctx_t*)ptr;
    // 删除定时器 
    if(relay_ctx)
    {
        relay_ctx->refcount--;
        if(relay_ctx->refcount <= 0)
        {
            ngx_http_live_play_relay_loc_conf_t* hrlc = relay_ctx->relay_conf;
            ngx_event_t *ev = &relay_ctx->netcall_timeout_ev;
            if(ev->timer_set){
                ngx_del_timer(ev);
             }

             ngx_http_close_rtmp_relay_pull(ptr);

            if(relay_ctx->cs && relay_ctx->cs->pc )
            {
                relay_ctx->cs->detached = 1;
                relay_ctx->cs->status_code = ngx_http_relay_play_close;
                ngx_http_live_netcall_close(relay_ctx->cs->pc->connection);
                relay_ctx->cs = NULL;
            }
            ngx_http_live_play_relay_free_ctx(relay_ctx,hrlc);
            ngx_printf_log("ngx_http_live_play_relay_module","ngx_http_live_relay_on_play_close","free relay ctx");
        }
    }
    return NGX_OK;
}

ngx_int_t ngx_http_get_relay_status(void* v)
{
    ngx_http_live_play_relay_loc_conf_t* hrlc;
    ngx_http_live_play_request_ctx_t *  rctx = (ngx_http_live_play_request_ctx_t*)v;
    hrlc = (ngx_http_live_play_relay_loc_conf_t*)ngx_http_get_module_loc_conf(rctx->s,ngx_http_live_play_relay_module);

     if(rctx && hrlc && rctx->relay_ctx)
     {
        ngx_http_live_play_relay_ctx_t *  hrctx = (ngx_http_live_play_relay_ctx_t*)rctx->relay_ctx;
        ngx_int_t count = hrlc->reconnect_count_before_302;
        // if(hrctx->reconnect_count >= count ) //重连次数太多/302跳转
        if(hrctx->reconnect_count >= count || hrctx->errcount >= count ) //重连次数太多/302跳转
            return NGX_STREAM_REWART;
        if(hrctx->rtmp_pull_url.len <= 7 && hrctx->http_pull_url.len > 7)
            return NGX_STREAM_REWART;   
            
        return NGX_OK;
     }
     return NGX_ERROR;
}
