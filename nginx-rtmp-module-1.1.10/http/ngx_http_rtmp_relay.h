#ifndef NGX_HTTP_RTMP_RELAY_H
#define NGX_HTTP_RTMP_RELAY_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"


ngx_int_t ngx_http_trigger_rtmp_relay_pull(void* v);

ngx_int_t ngx_http_close_rtmp_relay_pull(void*v);

void * get_http_to_rtmp_module_app_conf(void *v,ngx_module_t module);


#endif