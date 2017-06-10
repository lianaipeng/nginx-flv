#ifndef NGX_HTTP_LIVE_PLAY_RELAY_MODULE_H
#define NGX_HTTP_LIVE_PLAY_RELAY_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_relay_module.h"
// #include "ngx_http_rtmp_live_module.h"

typedef struct ngx_http_live_play_relay_ctx_s ngx_http_live_play_relay_ctx_t;

typedef ngx_chain_t * (*ngx_http_live_netcall_create_pt)(ngx_http_request_t *r,void *arg, ngx_pool_t *pool);
typedef ngx_int_t (*ngx_http_live_netcall_filter_pt)(ngx_chain_t *in);
typedef ngx_int_t (*ngx_http_live_netcall_sink_pt)(ngx_http_live_play_relay_ctx_t *hrctx,ngx_chain_t *in);
typedef ngx_int_t (*ngx_http_live_netcall_handle_pt)(ngx_http_live_play_relay_ctx_t *hrctx,void *arg, ngx_chain_t *in);


typedef struct {
    ngx_flag_t                                  active;
    ngx_flag_t                                  relay_redirect;
    ngx_str_t                                   secret_id;
    ngx_str_t                                   secret_key;
    
    ngx_str_t                                   rtmp_back_source_addr_param_name;
    ngx_str_t                                   http_back_source_addr_param_name;

    ngx_flag_t                                  relay_md5_on;
    ngx_str_t                                   http_on_play;
    ngx_str_t                                   method_name;
    ngx_msec_t                                  http_on_play_timeout;
    size_t                                      bufsize;

    ngx_uint_t                                   reconnect_count_before_302;

    ngx_url_t                                   *url;
    ngx_log_t                                   *log;
    ngx_pool_t                                   *pool;   
    ngx_uint_t                                   rtmp_server_port;   

    ngx_flag_t                                  check_ip;  //IP 规则检测标志
    ngx_str_t                                   ip_file_path ; //IP 库的路径   
      
    ngx_http_live_play_relay_ctx_t              *free_ctx; 
} ngx_http_live_play_relay_loc_conf_t;

typedef struct ngx_http_live_netcall_session_s {
    ngx_http_request_t                         *session;
    ngx_http_live_play_relay_ctx_t             *ctx;
    ngx_peer_connection_t                      *pc;
    ngx_url_t                                  *url;
    struct ngx_http_live_netcall_session_s     *next;
    void                                       *arg;
    ngx_http_live_netcall_handle_pt            handle;
    ngx_http_live_netcall_filter_pt            filter;
    ngx_http_live_netcall_sink_pt               sink;
    ngx_chain_t                                *in;
    ngx_chain_t                                *inlast;
    ngx_chain_t                                *out;
    ngx_msec_t                                  timeout;
    unsigned                                    detached:1;
    size_t                                      bufsize;

    ngx_uint_t                       netcall_ts;    // 回源开始时间
    ngx_uint_t                       status_code; 
} ngx_http_live_netcall_session_t;

typedef struct {
    ngx_url_t                           *url;
    ngx_http_live_netcall_create_pt      create;
    ngx_http_live_netcall_filter_pt      filter;
    ngx_http_live_netcall_sink_pt        sink;
    ngx_http_live_netcall_handle_pt      handle;
    void                                *arg;
    size_t                               argsize;
} ngx_http_live_netcall_init_t;

struct ngx_http_live_play_relay_ctx_s
{
    ngx_int_t                           active;
    ngx_int_t                           backing;
    ngx_int_t                           errcount;
    ngx_int_t                           reconnect_count;

    ngx_str_t                           http_pull_url;
    ngx_str_t                           rtmp_pull_url;
    ngx_str_t                           app;
    ngx_str_t                           stream;

    ngx_int_t                           url_len;
    ngx_int_t                           refcount;
    ngx_event_t                         netcall_timeout_ev;
    ngx_pool_t                         *pool;  
    ngx_rtmp_relay_ctx_t               *rctx;
    ngx_log_t                          *log;
    ngx_http_live_netcall_session_t    *cs;

    ngx_http_live_play_relay_loc_conf_t *relay_conf;
    
    void                               **main_conf;
    void                               **srv_conf;
    void                               **app_conf;

    ngx_rtmp_relay_app_conf_t           *racf;
    ngx_http_live_play_relay_ctx_t      *next;
};

extern ngx_module_t        ngx_http_live_play_relay_module;

ngx_int_t ngx_http_live_relay_on_play(void* r);


ngx_int_t ngx_http_live_relay_on_play_close(void * r);

ngx_int_t ngx_http_get_relay_status(void* v);
#endif
