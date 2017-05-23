#ifndef NGX_HTTP_PLAY_SCHEDULER_H
#define NGX_HTTP_PLAY_SCHEDULER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"

ngx_int_t ngx_http_live_play_process_slot(u_char * name,ssize_t len);

#endif