#include "ngx_http_rtmp_relay.h"
#include "ngx_http_live_play_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_http_rtmp_live_module.h"
#include "ngx_rtmp_edge_log.h"

extern ngx_rtmp_conf_ctx_t * ngx_rtmp_ctx;

typedef ngx_rtmp_relay_ctx_t * (* ngx_http_rtmp_relay_create_ctx_pt)
    (ngx_http_live_play_relay_ctx_t *rc, ngx_str_t *name, ngx_rtmp_relay_target_t *target);

ngx_int_t
ngx_http_rtmp_relay_push(ngx_http_live_play_relay_ctx_t *rc, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target);

static void
ngx_http_live_rtmp_relay_pull_reconnect(ngx_event_t *ev)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_ctx_t           *ctx, *pctx;
    ngx_uint_t                      n;
    ngx_rtmp_relay_target_t        *target, **t;
    //ngx_rtmp_relay_reconnect_t     *rrs, **prrs;  

    ngx_http_live_play_relay_ctx_t *relay_ctx = (ngx_http_live_play_relay_ctx_t*)ev->data;

    racf = relay_ctx->racf;
    ctx = relay_ctx->rctx;
    if (ctx == NULL) {
        return;
    }

   t = racf->pushes.elts;
    for (n = 0; n < racf->pushes.nelts; ++n, ++t) {
        target = *t;

        if (target->name.len && (ctx->name.len != target->name.len ||
            ngx_memcmp(ctx->name.data, target->name.data, ctx->name.len)))
        {
            continue;
        }

        for (pctx = ctx->play; pctx; pctx = pctx->next) {
            if (pctx->tag == &ngx_rtmp_relay_module &&
                pctx->data == target)
            {
                break;
            }
        }

        if (pctx) {
            continue;
        }

        if (ngx_http_rtmp_relay_push(relay_ctx, &ctx->name, target) == NGX_OK) {
            continue;
        }

        relay_ctx->reconnect_count++;

        if (!ctx->push_evt.timer_set) {
            ngx_add_timer(&ctx->push_evt, racf->push_reconnect);
        }
    }
}


static ngx_int_t
ngx_http_live_rtmp_stream_relay_copy_str(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    if (src->len == 0) {
        return NGX_OK;
    }
    dst->len = src->len;
    dst->data = ngx_palloc(pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->data, src->data, src->len);
    return NGX_OK;
}

static ngx_rtmp_relay_ctx_t *
ngx_http_live_rtmp_relay_create_remote_ctx(ngx_http_live_play_relay_ctx_t *relay_ctx, ngx_str_t* name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_rtmp_conf_ctx_t         cctx;
    ngx_printf_log("ngx_http_rtmp_relay","ngx_http_live_rtmp_relay_create_remote_ctx","relay: create remote context");

    cctx.app_conf = relay_ctx->app_conf;
    cctx.srv_conf = relay_ctx->srv_conf;
    cctx.main_conf = relay_ctx->main_conf;

    return ngx_rtmp_relay_create_connection(&cctx, name, target);
}

static ngx_rtmp_relay_ctx_t * ngx_http_live_rtmp_relay_create_local_ctx(ngx_http_live_play_relay_ctx_t *relay_ctx, 
                            ngx_str_t *name,ngx_rtmp_relay_target_t *target)
{
    ngx_rtmp_relay_ctx_t           *ctx = NULL;

    ngx_printf_log("ngx_http_rtmp_relay","ngx_http_live_rtmp_relay_create_local_ctx","relay: create local context");
    ctx = relay_ctx->rctx;    
    if (ctx == NULL) {
        ctx = ngx_pcalloc(relay_ctx->pool, sizeof(ngx_rtmp_relay_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }
        memset(ctx,0,sizeof(ngx_rtmp_relay_ctx_t));
    }

    ctx->session = NULL;
    ctx->push_evt.data = relay_ctx;
    ctx->push_evt.log = relay_ctx->log;
    ctx->push_evt.handler = ngx_http_live_rtmp_relay_pull_reconnect;

    if (ctx->publish) {
        return NULL;
    }

    if (ngx_http_live_rtmp_stream_relay_copy_str(relay_ctx->pool, &ctx->name, name)
            != NGX_OK)
    {
        return NULL;
    }

    return ctx;
}

static ngx_int_t ngx_http_live_rtmp_relay_create(ngx_http_live_play_relay_ctx_t *relay_ctx, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target,
        ngx_http_rtmp_relay_create_ctx_pt create_publish_ctx,
        ngx_http_rtmp_relay_create_ctx_pt create_play_ctx)
{
    ngx_rtmp_relay_ctx_t            *play_ctx, *publish_ctx;

    play_ctx = create_play_ctx(relay_ctx, name, target);
    if (play_ctx == NULL) {
        ngx_printf_log("ngx_http_rtmp_relay","ngx_http_live_rtmp_relay_create","create_play_ctx fail");
        return NGX_ERROR;
    }
    
    if ( relay_ctx->rctx ) {
        play_ctx->publish       = relay_ctx->rctx->publish;
        play_ctx->next          = relay_ctx->rctx->play;
        relay_ctx->rctx->play = play_ctx;
        return NGX_OK;
    }
    
    publish_ctx = create_publish_ctx(relay_ctx, name, target);
    if ( publish_ctx == NULL ) {
        if(play_ctx->session)
            ngx_rtmp_finalize_session(play_ctx->session);
        return NGX_ERROR;
    }
    
    publish_ctx->publish = publish_ctx;
    publish_ctx->play    = play_ctx;
    play_ctx->publish    = publish_ctx;
    relay_ctx->rctx    = publish_ctx;
    return NGX_OK;
}

ngx_int_t ngx_http_rtmp_relay_pull(ngx_http_live_play_relay_ctx_t *relay_ctx,ngx_str_t *name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_printf_log("ngx_http_rtmp_relay","ngx_http_rtmp_relay_pull","begin");
    return ngx_http_live_rtmp_relay_create(relay_ctx,name,target,
            ngx_http_live_rtmp_relay_create_remote_ctx,
            ngx_http_live_rtmp_relay_create_local_ctx);
}

ngx_int_t
ngx_http_rtmp_relay_push(ngx_http_live_play_relay_ctx_t *relay_ctx, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target)
{
     ngx_printf_log("ngx_http_rtmp_relay","ngx_http_rtmp_relay_push","begin");
    return ngx_http_live_rtmp_relay_create(relay_ctx, name, target,
            ngx_http_live_rtmp_relay_create_local_ctx,
            ngx_http_live_rtmp_relay_create_remote_ctx);
}

ngx_int_t ngx_http_trigger_rtmp_relay_pull(void* v)
{
    
    ngx_http_live_play_relay_ctx_t *prctx = NULL;
    ngx_rtmp_relay_target_t     target;
    ngx_str_t                   local_name;
    ngx_url_t                  *u;

    ngx_uint_t                   rtmp_server_port;
    ngx_rtmp_listen_t          *ls;
    ngx_rtmp_core_main_conf_t * cmcf;
    ngx_rtmp_core_srv_conf_t  **cscfs;
    ngx_rtmp_core_srv_conf_t  *cscf = NULL;
    ngx_rtmp_core_app_conf_t  **cacfp;
    ngx_uint_t   srv_num = 0;

    ngx_printf_log("ngx_http_rtmp_relay","ngx_http_trigger_rtmp_relay_pull","begin");
    prctx = (ngx_http_live_play_relay_ctx_t*)v;
    
    if(ngx_rtmp_ctx == NULL){
        return NGX_ERROR;
    }
    prctx->reconnect_count++;
    cmcf = (ngx_rtmp_core_main_conf_t*)ngx_rtmp_ctx->main_conf[ngx_rtmp_core_module.ctx_index];

    if (cmcf == NULL)
    {
        return NGX_ERROR;
    }

    cscfs = cmcf->servers.elts;
    srv_num = cmcf->servers.nelts;
    ls = cmcf->listen.elts;

    if(prctx->relay_conf == NULL)
        return NGX_ERROR;
    rtmp_server_port = prctx->relay_conf->rtmp_server_port;
   // cscf = (ngx_rtmp_core_srv_conf_t*)ngx_rtmp_ctx->srv_conf[ngx_rtmp_core_module.ctx_index];

    if(cscfs == NULL && srv_num > 0)
    {
        ngx_printf_log("ngx_http_rtmp_relay","ngx_http_trigger_rtmp_relay_pull","srv_num is null");
        return NGX_ERROR;
    }
    else
    {
        ngx_uint_t l = 0;
        for(l = 0; l < srv_num;l++){
            cscf = cscfs[l];
            struct sockaddr            *sa;
            struct sockaddr_in         *sin;
            sa = (struct sockaddr *) ls[l].sockaddr;
            sin = (struct sockaddr_in *) sa;
            ngx_uint_t port = ntohs(sin->sin_port);
            if(cscf && rtmp_server_port == port){
                cacfp = cscf->applications.elts;
                ngx_uint_t n = 0;
                for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
                    if ((*cacfp)->name.len == prctx->app.len &&
                    ngx_strncmp((*cacfp)->name.data, prctx->app.data, prctx->app.len) == 0)
                    {
                        /* found app! */
                        prctx->app_conf = (*cacfp)->app_conf;
                        break;
                    }
                }
                break;
            }
        }
    }

    if(cscf == NULL || prctx->app_conf == NULL)
    {
        ngx_printf_log("ngx_http_rtmp_relay","ngx_http_trigger_rtmp_relay_pull","connect: application not found:");
        return NGX_ERROR;
    }
    else
    {
        prctx->main_conf = ngx_rtmp_ctx->main_conf;
        prctx->srv_conf = cscf->ctx->srv_conf;
        //prctx->srv_conf = ngx_rtmp_ctx->srv_conf;
        prctx->racf = prctx->app_conf[ngx_rtmp_relay_module.ctx_index] ;
    }


    if (ngx_strncasecmp(prctx->rtmp_pull_url.data, (u_char *)"rtmp://", 7) != 0) {
        ngx_printf_log("ngx_http_rtmp_relay","ngx_http_trigger_rtmp_relay_pull","url format error");
        return NGX_ERROR;
    }
    ngx_memzero(&target, sizeof(target));

    local_name = prctx->stream;

    u = &target.url;
    u->url = local_name;
    u->url.data = prctx->rtmp_pull_url.data + 7;
    u->url.len = prctx->rtmp_pull_url.len - 7;
    u->default_port = 1935;
    u->uri_part = 1;
    u->no_resolve = 0; /* not want ip here */

    if (ngx_parse_url(prctx->pool, u) != NGX_OK) {
        ngx_printf_log("ngx_http_rtmp_relay","ngx_http_trigger_rtmp_relay_pull","notify: pull failed");
        return NGX_ERROR;
    }

    return ngx_http_rtmp_relay_pull(prctx,&local_name,&target);
}

ngx_int_t ngx_http_close_rtmp_relay_pull(void*v)
{
    ngx_printf_log("ngx_http_rtmp_relay","ngx_http_close_rtmp_relay_pull","begin");
    ngx_http_live_play_relay_ctx_t *relay_ctx = (ngx_http_live_play_relay_ctx_t*)v;

    ngx_rtmp_relay_ctx_t  *ctx, **cctx;
    if( relay_ctx == NULL)
        return NGX_OK;

    ctx = relay_ctx->rctx;
    if (ctx == NULL) {
        return NGX_OK;
    }
    
    if (ctx->publish == NULL) {
        return NGX_OK;
    }
    
    if (ctx->push_evt.timer_set) {
        ngx_del_timer(&ctx->push_evt);
    }

    for (cctx = &ctx->play; *cctx; cctx = &(*cctx)->next) {
        (*cctx)->publish = NULL;
        if((*cctx)->session){
            ngx_rtmp_finalize_session((*cctx)->session);
            (*cctx)->session = NULL;
        }
    }
    ctx->publish = NULL;
    relay_ctx->rctx = NULL;
    return NGX_OK;
}


void * get_http_to_rtmp_module_app_conf(void *v,ngx_module_t module)
{
    ngx_uint_t                 rtmp_server_port;
    ngx_rtmp_listen_t          *ls;
    ngx_rtmp_core_main_conf_t * cmcf;
    ngx_rtmp_core_srv_conf_t  **cscfs;
    ngx_rtmp_core_srv_conf_t  *cscf = NULL;
    ngx_rtmp_core_app_conf_t  **cacfp;
    ngx_uint_t   srv_num = 0;
    ngx_http_live_play_relay_loc_conf_t* hrlc;
    ngx_http_request_t *r = (ngx_http_request_t*)v;
    ngx_http_live_play_request_ctx_t *  rctx = (ngx_http_live_play_request_ctx_t*)ngx_http_get_module_ctx(r,ngx_http_live_play_module);

    hrlc = (ngx_http_live_play_relay_loc_conf_t*)ngx_http_get_module_loc_conf(r,ngx_http_live_play_relay_module);

    if(ngx_rtmp_ctx == NULL)
    {
        ngx_printf_log("ngx_http_rtmp_relay","get_http_to_rtmp_module_app_conf","get rtmp modules config error");
        return NULL;
    }
    cmcf = (ngx_rtmp_core_main_conf_t*)ngx_rtmp_ctx->main_conf[ngx_rtmp_core_module.ctx_index];

    if (cmcf == NULL)
    {
        ngx_printf_log("ngx_http_rtmp_relay","get_http_to_rtmp_module_app_conf","ngx_rtmp_core_main_conf_t error");
        return NULL;
    }

    cscfs = cmcf->servers.elts;
    srv_num = cmcf->servers.nelts;
    ls = cmcf->listen.elts;

    rtmp_server_port = hrlc->rtmp_server_port;


    if(cscfs == NULL && srv_num > 0)
    {
        ngx_printf_log("ngx_http_rtmp_relay","get_http_to_rtmp_module_app_conf","srv_num is null");
        return NULL;
    }
    else
    {
        ngx_uint_t l = 0;
        for(l = 0; l < srv_num;l++){
            cscf = cscfs[l];
            struct sockaddr            *sa;
            struct sockaddr_in         *sin;
            sa = (struct sockaddr *) ls[l].sockaddr;
            sin = (struct sockaddr_in *) sa;
            ngx_uint_t port = ntohs(sin->sin_port);
            if(cscf && rtmp_server_port == port){
                cacfp = cscf->applications.elts;
                ngx_uint_t n = 0;
                for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
                    if ((*cacfp)->name.len == rctx->app.len &&
                    ngx_strncmp((*cacfp)->name.data, rctx->app.data, rctx->app.len) == 0)
                    {
                        /* found app! */
                        return (*cacfp)->app_conf[module.ctx_index];
                    }
                }
            }
        }
    }
    return NULL;
}
