
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_proxy_protocol.h"
#include "ngx_rtmp_edge_log.h"


static void ngx_rtmp_close_connection(ngx_connection_t *c);
static u_char * ngx_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len);


void
ngx_rtmp_init_connection(ngx_connection_t *c)
{
    ngx_uint_t             i;
    ngx_rtmp_port_t       *port;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_rtmp_in_addr_t    *addr;
    ngx_rtmp_session_t    *s;
    ngx_rtmp_addr_conf_t  *addr_conf;
    ngx_int_t              unix_socket;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
    ngx_rtmp_in6_addr_t   *addr6;
#endif

    ++ngx_rtmp_naccepted;

    /* find the server configuration for the address:port */

    /* AF_INET only */

    port = c->listening->servers;
    unix_socket = 0;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_rtmp_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client connected '%V'",
                  c->number, &c->addr_text);

    s = ngx_rtmp_init_session(c, addr_conf);
    if (s == NULL) {
        return;
    }

    /* only auto-pushed connections are
     * done through unix socket */

    s->auto_pushed = unix_socket;

    if (addr_conf->proxy_protocol) {
        ngx_rtmp_proxy_protocol(s);

    } else {
        ngx_rtmp_handshake(s);
    }
}

void 
ngx_rtmp_init_socket(ngx_rtmp_session_t *s)
{
    ngx_uint_t  current_ts = ngx_rtmp_current_msec();
    // u_char uuid[32] = {'\0'};
    ngx_memzero(s->uuid, 32);
    ngx_sprintf(s->uuid, "%l_%d", current_ts, s->connection->fd);
    
    // 获取client server ip
    struct sockaddr_in sa;
    int len = sizeof(sa);
        
    if (getsockname(s->connection->fd, (struct sockaddr *)&sa, (socklen_t *)&len) != 0) {
        return;
    }
    char *local_ip = inet_ntoa(sa.sin_addr);
    s->server_ip.len = ngx_strlen(local_ip);
    s->server_ip.data = ngx_pcalloc(s->connection->pool, s->server_ip.len+1);
    ngx_memzero(s->server_ip.data, s->server_ip.len+1);
    ngx_memcpy(s->server_ip.data, local_ip, s->server_ip.len);

    len = sizeof(sa); 
    if (getpeername(s->connection->fd, (struct sockaddr *)&sa, (socklen_t *)&len) != 0) {
        return;
    }
    char *peer_ip = inet_ntoa(sa.sin_addr);
    s->client_ip.len = ngx_strlen(peer_ip);
    s->client_ip.data = ngx_pcalloc(s->connection->pool, s->client_ip.len+1);
    ngx_memzero(s->client_ip.data, s->client_ip.len+1);
    ngx_memcpy(s->client_ip.data, peer_ip, s->client_ip.len);
    
    char host[1024] = {'\0'};
    ngx_memcpy(host, s->connection->addr_text.data, s->connection->addr_text.len);
    len = 0;
    while (host[len] != '/' && host[len] != '\0') {
        len++;
    }
    s->host.len = len;
    s->host.data = ngx_pcalloc(s->connection->pool, len+1);
    ngx_memzero(s->host.data, len+1);
    ngx_memcpy(s->host.data, host, len);
}

ngx_rtmp_session_t *
ngx_rtmp_init_session(ngx_connection_t *c, ngx_rtmp_addr_conf_t *addr_conf)
{

    ngx_rtmp_session_t             *s;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_error_log_ctx_t       *ctx;

    s = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_session_t) +
            sizeof(ngx_chain_t *) * ((ngx_rtmp_core_srv_conf_t *)
                addr_conf->ctx-> srv_conf[ngx_rtmp_core_module
                    .ctx_index])->out_queue);
    if (s == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;
    s->busy_time = s->current_time = 0;

    c->data = s;
    s->connection = c;

    ctx = ngx_palloc(c->pool, sizeof(ngx_rtmp_error_log_ctx_t));
    if (ctx == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_rtmp_log_error;
    c->log->data = ctx;
    c->log->action = NULL;

    c->rtmp_log->connection = c->number;
    c->rtmp_log->handler = ngx_rtmp_log_error;
    c->rtmp_log->data = ctx;
    c->rtmp_log->action = NULL;

    c->log_error = NGX_ERROR_INFO;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /*
    // 重定向error_log
    ngx_rtmp_core_app_conf_t       *cacf;
    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    ngx_set_connection_log(s->connection, cacf->error_log);
    */
    ngx_set_connection_log(s->connection, cscf->error_log);
    ngx_set_connection_rtmplog(s->connection, cscf->rtmp_log);
    ngx_rtmp_init_socket(s);

    if (global_log == NULL)
        global_log = cscf->error_log; 
    
    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_stream_t)
            * cscf->max_streams);
    if (s->in_streams == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

#if (nginx_version >= 1007005)
    ngx_queue_init(&s->posted_dry_events);
#endif

    s->epoch = ngx_current_msec;
    s->timeout = cscf->timeout;
    s->buflen = cscf->buflen;
    ngx_rtmp_set_chunk_size(s, NGX_RTMP_DEFAULT_CHUNK_SIZE);


    if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT, NULL, NULL) != NGX_OK) {
        // s->status_code = ngx_rtmp_fire_event_err;
        s->status_code = ngx_rtmp_connect_err;
        ngx_rtmp_finalize_session(s);
        return NULL;
    }

    return s;
}


static u_char *
ngx_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_error_log_ctx_t   *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", server: %V", s->addr_text);
    len -= p - buf;
    buf = p;

    return p;
}


static void
ngx_rtmp_close_connection(ngx_connection_t *c)
{
    ngx_pool_t                         *pool;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "close connection");

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    pool = c->pool;
    ngx_close_connection(c);
    ngx_destroy_pool(pool);
}


static void
ngx_rtmp_close_session_handler(ngx_event_t *e)
{
    ngx_rtmp_session_t                 *s;
    ngx_connection_t                   *c;
    ngx_rtmp_core_srv_conf_t           *cscf;

    s = e->data;
    c = s->connection;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "close session");

    ngx_rtmp_fire_event(s, NGX_RTMP_DISCONNECT, NULL, NULL);

    if (s->ping_evt.timer_set) {
        ngx_del_timer(&s->ping_evt);
    }

    if (s->in_old_pool) {
        ngx_destroy_pool(s->in_old_pool);
    }

    if (s->in_pool) {
        ngx_destroy_pool(s->in_pool);
    }

    ngx_rtmp_free_handshake_buffers(s);

    while (s->out_pos != s->out_last) {
        ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos++]);
        s->out_pos %= s->out_queue;
    }

    ngx_rtmp_close_connection(c);
}


void
ngx_rtmp_finalize_session(ngx_rtmp_session_t *s)
{
    ngx_event_t        *e;
    ngx_connection_t   *c;

    //liw
    if(s == NULL)
        return ; 

    c = s->connection;
    if (c->destroyed) {
        return;
    }

    // char *szformat = NULL;
    ngx_uint_t  current_ts = ngx_rtmp_current_msec();
    if (s->publishing == 1) {
        ngx_rtmp_edge_log(NGX_EDGE_RTMP, NGX_EDGE_PUSH_STOP, s, current_ts);
    } else {
        ngx_rtmp_edge_log(NGX_EDGE_RTMP, NGX_EDGE_PULL_STOP, s, current_ts);
    }
    
    c->destroyed = 1;
    e = &s->close;
    e->data = s;
    e->handler = ngx_rtmp_close_session_handler;
    e->log = c->log;

    ngx_post_event(e, &ngx_posted_events);
}
