#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_codec_module.h>
#include "ngx_http_rtmp_live_module.h"
#include "ngx_http_live_play_module.h"
#include "ngx_rtmp_to_flv_packet.h"
#include "ngx_http_rtmp_relay.h"
#include "ngx_rtmp_edge_log.h"

static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;


//static char * ngx_http_rtmp_live_set_hdl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_rtmp_live_postconfiguration(ngx_conf_t *cf);
static void * ngx_http_rtmp_live_create_srv_conf(ngx_conf_t *cf);
static char * ngx_http_rtmp_live_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static void * ngx_http_rtmp_live_create_app_conf(ngx_conf_t *cf);
static char * ngx_http_rtmp_live_merge_app_conf(ngx_conf_t *cf, void *parent, void *child);

// 处理配置项
static ngx_command_t ngx_http_rtmp_live_commands[] = 
{
    { ngx_string("hdl"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_http_rtmp_live_app_conf_t, hdl),
      NULL },

     { ngx_string("http_live_idle_streams"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_http_rtmp_live_app_conf_t, http_idle_streams),
      NULL },
    ngx_null_command 
};

static ngx_rtmp_module_t ngx_http_rtmp_live_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_rtmp_live_postconfiguration,     /* postconfiguration */
    
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
    
    ngx_http_rtmp_live_create_srv_conf,       /* create server configuration */
    ngx_http_rtmp_live_merge_srv_conf,        /* merge server configuration */
    
    ngx_http_rtmp_live_create_app_conf,       /* create location configuration */
    ngx_http_rtmp_live_merge_app_conf,        /* merge location configuration */
};

ngx_module_t ngx_http_rtmp_live_module = {
    NGX_MODULE_V1,
    &ngx_http_rtmp_live_module_ctx,           /* module context */
    ngx_http_rtmp_live_commands,              /* module directives */
    NGX_RTMP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING    
};

static ngx_http_rtmp_live_stream_t ** 
ngx_http_rtmp_live_get_stream(ngx_http_rtmp_live_app_conf_t *lacf, u_char *name, int create)
{
    ngx_http_rtmp_live_stream_t    **stream;
    size_t                      len;

    if (lacf == NULL) {
        return NULL;
    }

    len = ngx_strlen(name);
    stream = &lacf->streams[ngx_hash_key(name, len) % lacf->nbuckets];

    for (; *stream; stream = &(*stream)->next) {
        if (ngx_strcmp(name, (*stream)->name) == 0) {
            return stream;
        }
    }

    if (!create) {
        return NULL;
    }

    ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_get_stream","live: create stream %s", name);

    // PUSH_CACHE
    if (lacf->free_streams) {
        *stream = lacf->free_streams;
        lacf->free_streams = lacf->free_streams->next;
    } else {
        *stream = ngx_palloc(lacf->pool, sizeof(ngx_http_rtmp_live_stream_t));
    }

    ngx_memzero(*stream, sizeof(ngx_http_rtmp_live_stream_t));
    (*stream)->tag_buf_len = 1024 * 16;

    ngx_memcpy((*stream)->name, name,ngx_min(sizeof((*stream)->name) - 1, len));
    return stream;
}

static ngx_int_t 
ngx_http_rtmp_live_join(ngx_http_rtmp_live_app_conf_t *lacf, u_char *name, unsigned create, 
        unsigned publisher, ngx_pool_t *pool, ngx_int_t porcotol_type, void* ptr)
{
    ngx_http_rtmp_live_ctx_t            *ctx;
    ngx_http_rtmp_live_stream_t        **stream;

    if (lacf == NULL ||  ptr == NULL) {
        return NGX_ERROR;
    }

    if (porcotol_type == RTMP_PROTOCOL) {
        ngx_rtmp_session_t *s = (ngx_rtmp_session_t *)ptr;
        ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
        if (ctx) {
            ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_join","rtmp live: already joined");
            return NGX_OK;
        }
        if (ctx == NULL) {
            ctx = ngx_palloc(pool, sizeof(ngx_http_rtmp_live_ctx_t));
            ngx_rtmp_set_ctx(s, ctx, ngx_http_rtmp_live_module);
        }
        ngx_memzero(ctx, sizeof(*ctx));
        ctx->s = s;
    } else if(porcotol_type == HTTP_FLV_PROTOCOL) {
        ngx_http_live_play_request_ctx_t * hr = (ngx_http_live_play_request_ctx_t*)ptr;
        ctx = (ngx_http_rtmp_live_ctx_t*)hr->hr_ctx;

        if (ctx && ctx->stream) {
            ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_join","http live: already joined");
            return NGX_OK;
        }

        if (ctx == NULL) {
            ctx = ngx_palloc(pool, sizeof(ngx_http_rtmp_live_ctx_t));
            hr->hr_ctx = (void*)ctx;
        }
        ngx_memzero(ctx, sizeof(*ctx));
        ctx->http_ctx = hr;
    } else {
        return NGX_ERROR;
    }
    
    stream = ngx_http_rtmp_live_get_stream(lacf, name, publisher || create);
    
    if (stream == NULL) {
        ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_join","live: stream not found");
        //ngx_rtmp_finalize_session(s);
        return NGX_STREAM_NOT_FIND;
    }

    if (publisher) {
        if ((*stream)->publishing) {
            ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_join","live: already publishing");
            return NGX_OK;
        }
        (*stream)->publishing = 1;
    }

    ctx->stream = *stream;
    ctx->publishing = publisher;

    ctx->next = (*stream)->ctx;
    (*stream)->ctx = ctx;

    ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;
    return NGX_OK;
}

static ngx_int_t 
ngx_http_rtmp_live_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_http_rtmp_live_app_conf_t                 *lacf;
    ngx_http_rtmp_live_ctx_t                      *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_http_rtmp_live_module);

    if (lacf==NULL || !lacf->hdl) {
        goto next;
    }

    if (s->auto_pushed) {
        goto next;
    }
    ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_publish","json stream:%s",v->name);

    ngx_http_rtmp_live_join(lacf, v->name, 1,1,s->connection->pool,RTMP_PROTOCOL,(void*)s);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_http_rtmp_live_module);
    if (ctx==NULL) {
        ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_publish","join error");
        goto next;
    }
next:
    return next_publish(s, v);
}

ngx_int_t 
ngx_http_rtmp_live_play(void *http_ctx)
{
    if(http_ctx == NULL)
        return NGX_ERROR;

    ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_play","begin");
    ngx_http_rtmp_live_app_conf_t           *lacf;
    ngx_http_rtmp_live_ctx_t                *hr_ctx;
    ngx_int_t                               rc;
    ngx_http_live_play_request_ctx_t        *ctx = (ngx_http_live_play_request_ctx_t*)http_ctx;

    lacf = (ngx_http_rtmp_live_app_conf_t*)get_http_to_rtmp_module_app_conf(ctx->s,ngx_http_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }
    u_char  name[4096] = {0};
    ngx_str_format_string(ctx->stream,(char*)name);
    
    rc = ngx_http_rtmp_live_join(lacf, name,0,0,ctx->s->connection->pool,HTTP_FLV_PROTOCOL,(void*)ctx);
    
    if (ctx->hr_ctx == NULL) {
        return NGX_ERROR;
    }

    hr_ctx = (ngx_http_rtmp_live_ctx_t*)ctx->hr_ctx;
    
    if (rc == NGX_STREAM_NOT_FIND || hr_ctx->stream == NULL) {
        //触发回源流程
        if (ngx_http_live_relay_on_play((void*)ctx) == NGX_OK || ctx->relay_ctx) {
            //创建stream
            rc = ngx_http_rtmp_live_join(lacf, name,1,0,ctx->s->connection->pool,HTTP_FLV_PROTOCOL,(void*)ctx);
            if (rc == NGX_OK ) {
                hr_ctx->stream->relay_ctx = (void*)ctx->relay_ctx;
            } else {
                return NGX_ERROR;
            }
        } else {
            return NGX_ERROR;
        }
    } else if (rc == NGX_OK && hr_ctx->stream ) {
        ctx->relay_ctx = hr_ctx->stream->relay_ctx;
        if (ctx->relay_ctx) {
            if (ctx->relay_ctx->rtmp_pull_url.len <= 0 && ctx->relay_ctx->http_pull_url.len <= 0) {//表示需要回源
                //在此触发回源 
                if (ctx->relay_ctx->backing == 0) { //都请求回源
                    if (ngx_http_live_relay_on_play((void*)ctx) != NGX_OK)
                        return NGX_ERROR;
                }
            }else{
                if(hr_ctx->stream->streaming == 0 && hr_ctx->stream->publishing == 0 && ctx->relay_ctx->rctx == NULL) //表示没有上行推流
                    ngx_http_trigger_rtmp_relay_pull(ctx->relay_ctx);
            }
        }
    } else {
        return NGX_ERROR;
    }
    hr_ctx->conf = lacf;

    if(hr_ctx->stream->streaming != 1 || hr_ctx->stream->publishing != 1) {
        return NGX_STREAM_BACK_CC; //表示回源
    }
    return NGX_OK;
}

static ngx_int_t 
ngx_http_rtmp_live_update_video_av_header(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_http_rtmp_live_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_http_rtmp_live_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    
    if (ctx == NULL || ctx->stream == NULL || codec_ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->stream->width != codec_ctx->width
        ||ctx->stream->height != codec_ctx->height
        ||ctx->stream->frame_rate != codec_ctx->frame_rate
        ||ctx->stream->video_data_rate != codec_ctx->video_data_rate
        ||ctx->stream->video_codec_id != codec_ctx->video_codec_id) 
    {
        ctx->stream->width = codec_ctx->width;
        ctx->stream->height = codec_ctx->height;
        ctx->stream->frame_rate = codec_ctx->frame_rate;
        ctx->stream->video_data_rate = codec_ctx->video_data_rate;
        ctx->stream->video_codec_id = codec_ctx->video_codec_id;

        ctx->stream->audio_codec_id = codec_ctx->audio_codec_id;
        ctx->stream->sample_rate = codec_ctx->sample_rate;
        ctx->stream->sample_size = codec_ctx->sample_size;
        ctx->stream->audio_channels = codec_ctx->audio_channels;
        ctx->stream->flv_header_update = 1;
    }
    return NGX_OK;
}

static ngx_int_t 
ngx_http_rtmp_live_update_audio_av_header(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_http_rtmp_live_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_http_rtmp_live_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    
    if (ctx == NULL || ctx->stream == NULL || codec_ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->stream->audio_codec_id != codec_ctx->audio_codec_id
        ||ctx->stream->sample_rate != codec_ctx->sample_rate
        ||ctx->stream->sample_size != codec_ctx->sample_size
        ||ctx->stream->audio_channels != codec_ctx->audio_channels)
    {
        ctx->stream->width = codec_ctx->width;
        ctx->stream->height = codec_ctx->height;
        ctx->stream->frame_rate = codec_ctx->frame_rate;
        ctx->stream->video_data_rate = codec_ctx->video_data_rate;
        ctx->stream->video_codec_id = codec_ctx->video_codec_id;

        ctx->stream->audio_codec_id = codec_ctx->audio_codec_id;
        ctx->stream->sample_rate = codec_ctx->sample_rate;
        ctx->stream->sample_size = codec_ctx->sample_size;
        ctx->stream->audio_channels = codec_ctx->audio_channels;
        ctx->stream->flv_header_update = 1;

    }
    return NGX_OK;
}


static ngx_int_t 
ngx_http_rtmp_live_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_http_rtmp_live_ctx_t       *ctx,*pctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_http_rtmp_live_app_conf_t       *lacf;
    ngx_http_live_play_request_ctx_t   *req_ctx;

    ngx_uint_t                      meta_version = 0;
    ngx_uint_t                      csidx;
    uint32_t                        delta;
    ngx_rtmp_live_chunk_stream_t   *cs;
    ngx_rtmp_header_t               ch, lh, clh;
    ngx_chain_t                    *rpkt;

    unsigned int                    mlen = 0;
    u_char                          mtype = 0;
    lacf = ngx_rtmp_get_module_app_conf(s, ngx_http_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    if (!lacf->hdl || in == NULL  || in->buf == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_http_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    if (ctx->publishing == 0) {
        return NGX_OK;
    }
    s->current_time = h->timestamp;

    if(s->busy_time == 0)
        s->busy_time = s->current_time;

    ctx->stream->streaming = 1;

    csidx = !(h->type == NGX_RTMP_MSG_VIDEO);
    cs  = &ctx->cs[csidx];
    ngx_memzero(&ch, sizeof(ch));
    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = cs->csid;
    ch.type = h->type;
    lh = ch;

    if (cs->active) {
        lh.timestamp = cs->timestamp;
    }

    clh = lh;
    clh.type = (h->type == NGX_RTMP_MSG_AUDIO ? NGX_RTMP_MSG_VIDEO :
                                                NGX_RTMP_MSG_AUDIO);

    cs->active = 1;
    cs->timestamp = ch.timestamp;

    delta = ch.timestamp - lh.timestamp;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx) {
        if (h->type == NGX_RTMP_MSG_VIDEO) {
            /* Only H264 is supported */
            if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264) {
                return NGX_OK;
            }
            mtype = HTTP_FLV_VIDEO_TAG;
            if (ngx_rtmp_get_video_frame_type(in) == 1)
                mtype = HTTP_FLV_VIDEO_KEY_FRAME_TAG;
        } else if (h->type == NGX_RTMP_MSG_AUDIO) {
            if (codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_AAC)
                return NGX_OK;
            mtype = HTTP_FLV_AUDIO_TAG;
        }

        if (codec_ctx->meta) {
            meta_version = codec_ctx->meta_version;
        }
    } else { 
        return NGX_OK;
    }

    if (ngx_rtmp_is_codec_header(in)) {
        if (h->type == NGX_RTMP_MSG_VIDEO) {
            ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_av","update video codec packet");
            //更新sps
            ngx_http_rtmp_live_update_video_av_header(s, h, in);
        } else if (h->type == NGX_RTMP_MSG_AUDIO) {
            ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_av","update audio codec packet");
            ngx_http_rtmp_live_update_audio_av_header(s, h, in);
        }
        
        if (ctx->stream->flv_header_update) {
            if (ngx_http_flv_perpare_header(s, (void*)ctx, h) != NGX_OK)
                return NGX_OK;
        }
    }

    rpkt = ngx_media_data_cache_write(s, h, in, &ch, &lh, HTTP_FLV_PROTOCOL);
    if (rpkt == NULL)
        return NGX_OK;
    mlen = rpkt->buf->last - rpkt->buf->pos;

    // 获取当前时间 单位毫秒（打印日志使用）
    ngx_uint_t  current_ts = ngx_rtmp_current_msec();
    ngx_uint_t  peers = 0; 
    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx) {
            continue;
        }
        s->busy_time = s->current_time;
        req_ctx = pctx->http_ctx;
        cs = &pctx->cs[csidx];

        req_ctx->current_ts = current_ts;

        //if (meta_version != pctx->meta_version || ctx->stream->flv_header_update) {
        if (meta_version != pctx->meta_version && pctx->meta_version == 0) {
            ngx_int_t only_send_header = 1;

            if(meta_version != pctx->meta_version && pctx->meta_version == 0) // 判断是否发送头
            {
                if(ngx_http_live_play_send_http_header(req_ctx) !=  NGX_OK)
                    continue;
                only_send_header = 0;
            }
            pctx->cs[0].active = 0;
            pctx->cs[1].active = 0;

            if(ngx_media_data_cache_send(s,(void*)pctx,HTTP_FLV_PROTOCOL,only_send_header) != NGX_OK)
                continue;
            pctx->meta_version = meta_version;
        }else {
            unsigned int check_pts = ngx_http_check_tag_pts(rpkt,h->timestamp,cs->timestamp,delta);
            ngx_http_live_send_message(req_ctx,rpkt,mtype,mlen,check_pts,delta);
            cs->timestamp += delta;
            req_ctx->current_time = cs->timestamp;
        }

        peers++;
    }

    
    if (h->type == NGX_RTMP_MSG_AUDIO) {
        s->send_audio_size += mlen * peers;
    } else if (h->type == NGX_RTMP_MSG_VIDEO) {
        s->send_video_size += mlen * peers;       
        s->send_video_frame += peers;
    }
    
    ctx->stream->flv_header_update = 0;

    //判断如果冷流在一定时间内没有人观看，则把流断开，防止上行带宽过载浪费
    if(ngx_rtmp_check_up_idle_stream(s,HTTP_FLV_PROTOCOL) !=  NGX_OK){
        ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_av","close idle stream");
        ngx_rtmp_finalize_session(s);
    }
    return NGX_OK;
}


static ngx_int_t 
ngx_http_rtmp_live_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    return next_stream_begin(s, v);
}

static ngx_int_t 
ngx_http_rtmp_live_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{

    return next_stream_eof(s, v);
}

static ngx_int_t 
ngx_http_rtmp_live_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_http_rtmp_live_app_conf_t   *lacf;
    ngx_http_rtmp_live_ctx_t * hr_ctx,**cctx,*pctx;
    ngx_http_rtmp_live_stream_t        **stream;
    ngx_http_live_play_request_ctx_t   *http_ctx = NULL;

    ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_close_stream","begin");

    hr_ctx = ngx_rtmp_get_module_ctx(s, ngx_http_rtmp_live_module);
    if (hr_ctx == NULL || hr_ctx->stream == NULL)
        goto next;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_http_rtmp_live_module);
    if (lacf == NULL) {
        goto next;
    }

    if (hr_ctx->stream->publishing && hr_ctx->publishing) {
        ngx_media_data_cahce_clear(s,HTTP_FLV_PROTOCOL);
        hr_ctx->stream->publishing = 0;
        hr_ctx->stream->streaming = 0;

        ngx_http_close_rtmp_relay_pull(hr_ctx->stream->relay_ctx);
    }

    for (cctx = &hr_ctx->stream->ctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == hr_ctx) {
            *cctx = hr_ctx->next;
            break;
        }
    }

    if (hr_ctx->publishing) {
         ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_close_stream","close publish");
        if (!lacf->http_idle_streams) {
            for (pctx = hr_ctx->stream->ctx; pctx; pctx = pctx->next) {
                if (pctx->publishing == 0) {
                    http_ctx = pctx->http_ctx;
                    http_ctx->status_code = ngx_rtmp_live_idle_publisher;
                    ngx_http_live_play_close(http_ctx);
                }
            }
        }
    }

    if (hr_ctx->stream->ctx) {
        hr_ctx->stream = NULL;
        hr_ctx->http_ctx = NULL;
        goto next;
    }

    stream = ngx_http_rtmp_live_get_stream(lacf, hr_ctx->stream->name, 0);
    if (stream == NULL) {
        goto next;
    }

    //删除转推
    if (hr_ctx->stream->relay_ctx) {
        ngx_http_live_relay_on_play_close((void*)(*stream)->relay_ctx);
        (*stream)->relay_ctx = NULL;
    }

    *stream = (*stream)->next;
    hr_ctx->stream->next = lacf->free_streams;
    lacf->free_streams = hr_ctx->stream;
    hr_ctx->stream = NULL;
    ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_close_stream","free stream");
next:
    return next_close_stream(s, v);
}
 
ngx_int_t 
ngx_http_rtmp_live_close_play_stream(void* http_ctx)
{
    ngx_http_rtmp_live_app_conf_t   *lacf;
    ngx_http_rtmp_live_ctx_t * hr_ctx,**cctx;
    ngx_http_rtmp_live_stream_t        **stream;
    ngx_http_live_play_request_ctx_t   *ctx = (ngx_http_live_play_request_ctx_t*)http_ctx;

    if(ctx == NULL)
        return NGX_ERROR;
    hr_ctx = (ngx_http_rtmp_live_ctx_t*)ctx->hr_ctx;

    if(hr_ctx == NULL || hr_ctx->stream == NULL)
        return NGX_ERROR;

    lacf = (ngx_http_rtmp_live_app_conf_t*)hr_ctx->conf;
    
    if(lacf == NULL)
    {
        ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_close_play_stream","get conf error");
        return NGX_ERROR;
    }
    ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_close_play_stream","begin");

    for (cctx = &hr_ctx->stream->ctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == hr_ctx) {
            *cctx = hr_ctx->next;
             ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_close_play_stream","find ctx");
            break;
        }
    }

    if (hr_ctx->stream->ctx) {
        hr_ctx->stream = NULL;
        ctx->relay_ctx = NULL;
        goto next;
    }

    stream = ngx_http_rtmp_live_get_stream(lacf, hr_ctx->stream->name, 0);
    if (stream == NULL) {
        goto next;
    }

    //删除转推
    if(ctx->relay_ctx && ctx->relay_ctx == (*stream)->relay_ctx )
    {
        ngx_http_live_relay_on_play_close((*stream)->relay_ctx);
        ctx->relay_ctx = NULL;
        (*stream)->relay_ctx = NULL;
    }

    *stream = (*stream)->next;
    hr_ctx->stream->next = lacf->free_streams;
    lacf->free_streams = hr_ctx->stream;
    hr_ctx->stream = NULL;
    ngx_printf_log("ngx_http_rtmp_live_module","ngx_http_rtmp_live_close_play_stream","free stream");
next:
    return NGX_OK;
}

static void * 
ngx_http_rtmp_live_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_rtmp_live_srv_conf_t           *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rtmp_live_srv_conf_t));

    if (conf==NULL) {
        return NULL;
    }
    return conf;
}

static char *
ngx_http_rtmp_live_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    (void)cf;
    (void)parent;
    (void)child;
    return NGX_CONF_OK;    
}

static void * 
ngx_http_rtmp_live_create_app_conf(ngx_conf_t *cf)
{
    ngx_http_rtmp_live_app_conf_t          *hracf;
        
    hracf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rtmp_live_app_conf_t));
    if (hracf == NULL) {
        return NULL;
    }

    hracf->hdl = NGX_CONF_UNSET;
    hracf->nbuckets = NGX_CONF_UNSET;
    hracf->http_idle_streams = NGX_CONF_UNSET;
    return hracf;
}

static char *
ngx_http_rtmp_live_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_rtmp_live_app_conf_t    *prev = parent;   // 上层
    ngx_http_rtmp_live_app_conf_t    *conf = child;    // 下层
    
    ngx_conf_merge_value(conf->hdl, prev->hdl, 0);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);
    ngx_conf_merge_value(conf->http_idle_streams, prev->http_idle_streams, 1);
    conf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
    if (conf->pool == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->streams = ngx_pcalloc(cf->pool,
            sizeof(ngx_rtmp_live_stream_t *) * conf->nbuckets);
    
    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_http_rtmp_live_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t               *cmcf;
    ngx_rtmp_handler_pt                     *h;
    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_http_rtmp_live_av;
    
    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_http_rtmp_live_av;
    
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_http_rtmp_live_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_http_rtmp_live_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_http_rtmp_live_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_http_rtmp_live_stream_eof;
    return NGX_OK;
}



