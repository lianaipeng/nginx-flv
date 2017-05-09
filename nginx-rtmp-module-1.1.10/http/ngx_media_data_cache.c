#include "ngx_media_data_cache.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_http_rtmp_live_module.h"
#include "ngx_rtmp_to_flv_packet.h"

static ngx_media_data_node_t*  alloc_media_node(ngx_media_data_cache_t* cache,ngx_pool_t* pool)
{
    ngx_media_data_node_t * node = NULL;
    if(cache && pool)
    {
        if(cache->free_node_list)
        {
            node = cache->free_node_list;
            cache->free_node_list = node->next;
            node->next = NULL;
        }
        else
        {
            node = (ngx_media_data_node_t*)ngx_palloc(pool, sizeof(ngx_media_data_node_t));
        }
        if(node)
        {
            memset(node,0,sizeof(ngx_media_data_node_t));
        }
    }
    return node;
}

static void  free_media_node(ngx_media_data_cache_t* cache,ngx_media_data_node_t* node)
{
    if(cache && node)
    {
        memset(node,0,sizeof(ngx_media_data_node_t));
        node->next = cache->free_node_list;
        cache->free_node_list = node;
    }
}

int vide_frame = 0;
//rtmp cache
ngx_chain_t* ngx_rtmp_media_data_cache_write(ngx_rtmp_session_t* s, ngx_rtmp_header_t *h, 
        ngx_chain_t* in,ngx_rtmp_header_t *ch, ngx_rtmp_header_t *lh,ngx_int_t type)
{
    if (type == RTMP_PROTOCOL)
    {
        ngx_chain_t* rpkt = NULL;
        ngx_rtmp_live_app_conf_t       *lacf = NULL;
        ngx_rtmp_live_ctx_t            *ctx = NULL;
        ngx_media_data_node_t          *node = NULL;
        ngx_rtmp_core_srv_conf_t       *cscf = NULL;
        ngx_int_t                      htype = 0;
        lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
        ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
        if (cscf == NULL || lacf == NULL || ctx == NULL || ctx->stream == NULL) {
            return NULL;
        }

        if(lacf->cache_gop_duration == 0 && lacf->cache_gop_num == 0)
            return rpkt;

        if(ctx->media_cache == NULL)
        {
            ctx->media_cache = (ngx_media_data_cache_t*)ngx_palloc(s->connection->pool, sizeof(ngx_media_data_cache_t));
            if(ctx->media_cache == NULL)
                return NULL;
            memset(ctx->media_cache,0,sizeof(ngx_media_data_cache_t));
            ctx->media_cache->s = s;
            ctx->media_cache->cache_gop_num = 0;
        }

        if(h->type == NGX_RTMP_MSG_VIDEO)
            htype = ngx_rtmp_get_video_frame_type(in);

        if((htype != 1) 
        && (ctx->media_cache->cache_duration == 0 && ctx->media_cache->video_cache_frame_num == 0))
        {
            return rpkt;
        }
        rpkt = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
        if(rpkt == NULL)
            return NULL;

        ngx_rtmp_prepare_message(s, ch, lh, rpkt);


        node = alloc_media_node(ctx->media_cache,s->connection->pool);
        if(node)
        { 
            node->mtype = h->type;
            node->mcpts = ch->timestamp;
            node->mlpts = lh->timestamp;
            node->delta = ch->timestamp - lh->timestamp;
            node->key_frame = htype;
            node->prio = (h->type == NGX_RTMP_MSG_VIDEO ? node->key_frame : 0);
            node->cache_chain = rpkt;
            node->next = NULL;

            if(node->key_frame == 1 )
            {
                //printf("video gop size is %d\n",vide_frame);
                vide_frame = 0;
            }

            if(ctx->media_cache->busy_cache_head == NULL)
            {
                 ctx->media_cache->busy_cache_head = node;
                ctx->media_cache->busy_cache_tail = ctx->media_cache->busy_cache_head;
            }
            else
            {
                ctx->media_cache->busy_cache_tail->next = node;
                ctx->media_cache->busy_cache_tail = node;
            }

            if(node->key_frame == 1)
            {
                ctx->media_cache->cache_gop_num++;
            }

            if(h->type == NGX_RTMP_MSG_AUDIO)
            {
                ctx->media_cache->audio_cache_frame_num++;
                ctx->media_cache->audio_cache_duration += node->delta;
            }
            else if(h->type == NGX_RTMP_MSG_VIDEO)
            {
                ctx->media_cache->video_cache_frame_num++;
                 vide_frame++;
                ctx->media_cache->video_cache_duration += node->delta;
            }
            ctx->media_cache->cache_duration 
            = ctx->media_cache->audio_cache_duration > ctx->media_cache->video_cache_duration 
            ? ctx->media_cache->audio_cache_duration : ctx->media_cache->video_cache_duration;

            //if(lacf->cache_gop_duration < ctx->media_cache->cache_duration
           if( lacf->cache_gop_num < ctx->media_cache->cache_gop_num)
            {
                if(node->key_frame == 1)
                {
                    ctx->media_cache->cache_gop_num--;

                    ngx_media_data_node_t * ln = ctx->media_cache->busy_cache_head;
                    ctx->media_cache->busy_cache_head = ln->next;

                    //printf("delete video frame num %ld  audio frame num %ld ,gop num %ld\n"
                    //,ctx->media_cache->video_cache_frame_num,ctx->media_cache->audio_cache_frame_num
                    //,ctx->media_cache->cache_gop_num);
                    int vide_delframe = 0;
                    while(ln)
                    {
                        //printf("delete frame  %ld\n",ln->mtype);
                        if(ln->mtype == NGX_RTMP_MSG_AUDIO)
                        {
                            ctx->media_cache->audio_cache_frame_num--;
                            ctx->media_cache->audio_cache_duration -= ln->delta;
                        }
                        else if(ln->mtype == NGX_RTMP_MSG_VIDEO)
                        {
                            ctx->media_cache->video_cache_frame_num--;
                            vide_delframe++;
                            ctx->media_cache->video_cache_duration -= ln->delta;
                        }

                        ctx->media_cache->cache_duration = 
                        ctx->media_cache->audio_cache_duration > ctx->media_cache->video_cache_duration
                        ? ctx->media_cache->audio_cache_duration : ctx->media_cache->video_cache_duration;

                        ngx_rtmp_free_shared_chain(cscf, ln->cache_chain);
                        free_media_node(ctx->media_cache,ln);

                        ln = ctx->media_cache->busy_cache_head;
                        if(ln == NULL )
                        {
                            //printf("meadia cache queue empty break\n");
                            break;  
                        }
                        if(ln->key_frame == 1 && ln->mtype == NGX_RTMP_MSG_VIDEO)
                        {
                            break; 
                        }

                        ctx->media_cache->busy_cache_head = ln->next;
                    }

                     //printf("video frame num %ld  audio frame num %ld ,gop num %ld del video frame %d\n"
                    //,ctx->media_cache->video_cache_frame_num,ctx->media_cache->audio_cache_frame_num
                    //,ctx->media_cache->cache_gop_num,vide_delframe);
                }
            }
        }
        return rpkt;
    }
    return NULL;
}

int http_video_frame = 0;
//http flv cache
ngx_chain_t* 
ngx_http_flv_media_data_cache_write(ngx_rtmp_session_t* s, ngx_rtmp_header_t *h, ngx_chain_t* in,
        ngx_rtmp_header_t *ch, ngx_rtmp_header_t *lh, ngx_int_t type)
{
    if (type != HTTP_FLV_PROTOCOL) {
        return NULL;
    }

    ngx_chain_t* rpkt = NULL;
    ngx_rtmp_live_app_conf_t       *lacf = NULL;
    ngx_http_rtmp_live_ctx_t       *ctx = NULL;
    ngx_media_data_node_t          *node = NULL;
    ngx_rtmp_core_srv_conf_t       *cscf = NULL;
    ngx_int_t                      htype = 0;
    unsigned int                   tag_size = 0;
    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_http_rtmp_live_module);
    if (cscf == NULL || lacf == NULL || ctx == NULL || ctx->stream == NULL) {
        return NULL;
    }

    if (lacf->cache_gop_duration == 0 && lacf->cache_gop_num == 0)
        return rpkt;

    if (ctx->media_cache == NULL) {
        ctx->media_cache = (ngx_media_data_cache_t*)ngx_palloc(s->connection->pool, sizeof(ngx_media_data_cache_t));
        if(ctx->media_cache == NULL)
            return NULL;
        memset(ctx->media_cache,0,sizeof(ngx_media_data_cache_t));
        ctx->media_cache->s = s;
        ctx->media_cache->cache_gop_num = 0;
    }

    if (h->type == NGX_RTMP_MSG_VIDEO)
        htype = ngx_rtmp_get_video_frame_type(in);

    if ((htype != 1) && 
            (ctx->media_cache->cache_duration == 0 && ctx->media_cache->video_cache_frame_num == 0))
    {
        return rpkt;
    }

    // 申请内存
    rpkt = ngx_http_flv_base_alloc_tag_mem(h->mlen);
    if (rpkt == NULL)
        return NULL;

    // 组装tag 
    if (ngx_http_flv_prepare_message(h, in, rpkt, &tag_size) != NGX_OK) {
        ngx_http_flv_free_tag_mem(rpkt);
        return NULL;
    }

    node = alloc_media_node(ctx->media_cache, s->connection->pool);
    if (node) { 
        node->mtype = h->type;
        node->mcpts = ch->timestamp;
        node->mlpts = lh->timestamp;
        node->delta = ch->timestamp - lh->timestamp;
        node->key_frame = htype;
        node->prio = (h->type == NGX_RTMP_MSG_VIDEO ? node->key_frame : 0);
        node->cache_chain = rpkt;
        node->next = NULL;

        if (node->key_frame == 1 ) {
            printf("http flv video gop size is %d\n",http_video_frame);
            http_video_frame = 0;
        }

        if (ctx->media_cache->busy_cache_head == NULL) {
            ctx->media_cache->busy_cache_head = node;
            ctx->media_cache->busy_cache_tail = ctx->media_cache->busy_cache_head;
        } else {
            ctx->media_cache->busy_cache_tail->next = node;
            ctx->media_cache->busy_cache_tail = node;
        }

        if (node->key_frame == 1) {
            ctx->media_cache->cache_gop_num++;
        }

        if (h->type == NGX_RTMP_MSG_AUDIO) {
            ctx->media_cache->audio_cache_frame_num++;
            ctx->media_cache->audio_cache_duration += node->delta;
        } else if (h->type == NGX_RTMP_MSG_VIDEO) {
            ctx->media_cache->video_cache_frame_num++;
            http_video_frame++;
            ctx->media_cache->video_cache_duration += node->delta;
        }
        ctx->media_cache->cache_duration 
            = ctx->media_cache->audio_cache_duration > ctx->media_cache->video_cache_duration 
            ? ctx->media_cache->audio_cache_duration : ctx->media_cache->video_cache_duration;

        //if(lacf->cache_gop_duration < ctx->media_cache->cache_duration
        if (lacf->cache_gop_num < ctx->media_cache->cache_gop_num) {
            if (node->key_frame == 1) {
                ctx->media_cache->cache_gop_num--;

                ngx_media_data_node_t * ln = ctx->media_cache->busy_cache_head;
                ctx->media_cache->busy_cache_head = ln->next;

                printf("http flv delete video frame num %ld  audio frame num %ld ,gop num %ld\n"
                        ,ctx->media_cache->video_cache_frame_num,ctx->media_cache->audio_cache_frame_num
                        ,ctx->media_cache->cache_gop_num);
                int vide_delframe = 0;
                while (ln) {
                    //printf("delete frame  %ld\n",ln->mtype);
                    if (ln->mtype == NGX_RTMP_MSG_AUDIO) {
                        ctx->media_cache->audio_cache_frame_num--;
                        ctx->media_cache->audio_cache_duration -= ln->delta;
                    } else if(ln->mtype == NGX_RTMP_MSG_VIDEO) {
                        ctx->media_cache->video_cache_frame_num--;
                        vide_delframe++;
                        ctx->media_cache->video_cache_duration -= ln->delta;
                    }

                    ctx->media_cache->cache_duration = 
                        ctx->media_cache->audio_cache_duration > ctx->media_cache->video_cache_duration
                        ? ctx->media_cache->audio_cache_duration : ctx->media_cache->video_cache_duration;

                    //ngx_rtmp_free_shared_chain(cscf, ln->cache_chain);

                    ngx_http_flv_free_tag_mem(ln->cache_chain);
                    free_media_node(ctx->media_cache,ln);

                    ln = ctx->media_cache->busy_cache_head;
                    if (ln == NULL ) {
                        printf("http flv meadia cache queue empty break\n");
                        break;  
                    }
                    if (ln->key_frame == 1 && ln->mtype == NGX_RTMP_MSG_VIDEO) {
                        break; 
                    }

                    ctx->media_cache->busy_cache_head = ln->next;
                }

                printf("http flv video frame num %ld  audio frame num %ld ,gop num %ld del video frame %d\n"
                        ,ctx->media_cache->video_cache_frame_num,ctx->media_cache->audio_cache_frame_num
                        ,ctx->media_cache->cache_gop_num,vide_delframe);
            }
        }
    }
    return rpkt;
}

ngx_chain_t* 
ngx_media_data_cache_write(ngx_rtmp_session_t* s, ngx_rtmp_header_t *h, ngx_chain_t* in, 
        ngx_rtmp_header_t *ch, ngx_rtmp_header_t *lh, ngx_int_t type)
{
    if (ngx_rtmp_is_codec_header(in))
        return NULL;
        
    if (type == RTMP_PROTOCOL) {
        return ngx_rtmp_media_data_cache_write(s,h,in,ch,lh,type);
    } else if(type == HTTP_FLV_PROTOCOL) {
        return ngx_http_flv_media_data_cache_write(s,h,in,ch,lh,type);
    }
    return NULL;
}

ngx_int_t ngx_rtmp_media_data_cache_send(ngx_rtmp_session_t* s,void* ptrctx)
{
    ngx_chain_t* rpkt = NULL;
    ngx_chain_t* apkt = NULL;
    ngx_chain_t* vpkt = NULL;
    ngx_rtmp_live_app_conf_t       *lacf = NULL;
    ngx_rtmp_live_ctx_t            *ctx = NULL;
    ngx_rtmp_live_ctx_t            *pctx = NULL;
    ngx_rtmp_core_srv_conf_t       *cscf = NULL;
    ngx_media_data_cache_t         *cache = NULL;
    ngx_rtmp_session_t* ss = NULL;
    ngx_int_t   rc;

    ngx_rtmp_live_chunk_stream_t   *vcs = NULL;
    ngx_rtmp_live_chunk_stream_t   *acs = NULL;

    pctx = (ngx_rtmp_live_ctx_t*)ptrctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    

    if (cscf == NULL || lacf == NULL || ctx == NULL || pctx == NULL) {
            return NGX_OK;
    }
    ss = pctx->session;
    cache = ctx->media_cache;

    vcs = &pctx->cs[0];
    acs = &pctx->cs[1];

    if(cache == NULL ||  ss == NULL || cache->busy_cache_head == NULL)
    {
        //printf("cache  is empty\n");
        return NGX_OK;
    }

    if(cache->aac_header == NULL || cache->avc_header == NULL )
    {
        //printf("aac or avc header is empty\n");
        return NGX_OK;
    }

    if(cache->aac_header && !acs->active){
       // printf("send audio aac header\n");
        if (apkt == NULL) {
            ngx_rtmp_header_t lh;

            //lh.timestamp = cache->busy_cache_head->mcpts;
            lh.timestamp = 0;
            lh.msid = NGX_RTMP_MSID;
            lh.csid = acs->csid;
            lh.type = NGX_RTMP_MSG_AUDIO;

            apkt = ngx_rtmp_append_shared_bufs(cscf, NULL, cache->aac_header);
            ngx_rtmp_prepare_message(s, &lh, NULL, apkt);
        }

        rc = ngx_rtmp_send_message(ss, apkt, 0);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        acs->timestamp = 0;//cache->busy_cache_head->mcpts;
        acs->active = 1;
        ss->current_time = acs->timestamp;
    }

    if(cache->avc_header && !vcs->active){
        // printf("send video avc header\n");
        if (vpkt == NULL) {
            ngx_rtmp_header_t lh;
            //lh.timestamp = cache->busy_cache_head->mcpts;
            lh.timestamp = 0;
            lh.msid = NGX_RTMP_MSID;
            lh.csid = vcs->csid;
            lh.type = NGX_RTMP_MSG_VIDEO;

            vpkt = ngx_rtmp_append_shared_bufs(cscf, NULL, cache->avc_header);
            ngx_rtmp_prepare_message(s, &lh, NULL, vpkt);
        }

        rc = ngx_rtmp_send_message(ss, vpkt, 0);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        vcs->timestamp = 0;//cache->busy_cache_head->mcpts;
        vcs->active = 1;
        ss->current_time = vcs->timestamp;
    }

    if(!vcs->active || !acs->active)
        return NGX_OK;
    
    //printf("send data\n");
    ngx_media_data_node_t * ln = cache->busy_cache_head;

    while(ln)
    {
        ngx_rtmp_live_chunk_stream_t * cs = NULL;
        ngx_uint_t   delta = 0;

        if(ln->mtype == NGX_RTMP_MSG_AUDIO)
        {
            cs = acs;
        }
        else if(ln->mtype == NGX_RTMP_MSG_VIDEO)
        {
            cs = vcs;
        }
        else
        {
            continue;
        }

        rpkt = ln->cache_chain;
        delta = ln->delta;

        int mlen = 0;
        ngx_chain_t * l;
        for(l = rpkt; l; l = l->next) {
            mlen += (l->buf->last - l->buf->pos);
        }

        if (ngx_rtmp_send_message(ss, rpkt, ln->prio) != NGX_OK) {
            ++pctx->ndropped;
            cs->dropped += delta;
                //printf("***send packet error\n");
        }

        const char                     *type_s;
        type_s = (ln->mtype == NGX_RTMP_MSG_VIDEO ? "video" : "audio");
        cs->timestamp += delta;
        ss->current_time = cs->timestamp;
        //printf("send packet %s  pts %d size %d\n",type_s,cs->timestamp,mlen);
        
        ln = ln->next;
        if(ln ==NULL)
            break;
    }
    return NGX_OK;
}

ngx_int_t 
ngx_http_flv_send_header(ngx_rtmp_session_t *s, void *ptr)
{
    ngx_rtmp_live_app_conf_t       *lacf = NULL;
    ngx_http_rtmp_live_ctx_t       *ctx = NULL;
    ngx_http_live_play_request_ctx_t* ss = NULL;
    ngx_int_t   rc; 

    ngx_rtmp_live_chunk_stream_t   *vcs = NULL;
    ngx_rtmp_live_chunk_stream_t   *acs = NULL;
    ngx_http_rtmp_live_ctx_t* pctx = (void*)ptr;
    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_http_rtmp_live_module);

    if (lacf == NULL || ctx == NULL || pctx == NULL) {
        return NGX_ERROR;
    }

    vcs = &pctx->cs[0];
    acs = &pctx->cs[1];

    ss = pctx->http_ctx;

    if (ctx->stream->aac_tag_size <= 0 
        || ctx->stream->avc_tag_size <= 0 
        || ctx->stream->meta_tag_size <= 0) {
        printf("http flv header error\n");
        return NGX_ERROR;
    }
    
    if (ctx->stream->aac_tag_size > 0){
        printf("send flv header\n");
        rc = ngx_http_live_send_message(ss, ctx->stream->meta_conf_tag, HTTP_FLV_META_TAG ,ctx->stream->aac_tag_size, 0, 0);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    if (!acs->active && ctx->stream->aac_tag_size > 0){
        printf("send audio aac header\n");
        rc = ngx_http_live_send_message(ss, ctx->stream->aac_conf_tag, HTTP_FLV_AAC_TAG, ctx->stream->aac_tag_size, 0, 0);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
        acs->timestamp = 0;//cache->busy_cache_head->mcpts;
        acs->active = 1;
        ss->current_time = acs->timestamp;
    }

    if (!vcs->active && ctx->stream->avc_tag_size > 0){
        printf("send video avc header\n");
        rc = ngx_http_live_send_message(ss, ctx->stream->avc_conf_tag, HTTP_FLV_AVC_TAG, ctx->stream->avc_tag_size, 0, 0);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
        vcs->timestamp = 0;//cache->busy_cache_head->mcpts;
        vcs->active = 1;
        ss->current_time = vcs->timestamp;
    }
    if (!vcs->active || !acs->active )
        return NGX_ERROR;
    return NGX_OK;
}

ngx_int_t 
ngx_http_flv_media_data_cache_send(ngx_rtmp_session_t *s, void *ptrctx)
{
    ngx_chain_t* rpkt = NULL;

    ngx_rtmp_live_app_conf_t       *lacf = NULL;
    ngx_http_rtmp_live_ctx_t       *ctx = NULL;
    ngx_http_rtmp_live_ctx_t       *pctx = NULL;
    ngx_rtmp_core_srv_conf_t       *cscf = NULL;
    ngx_media_data_cache_t         *cache = NULL;
    ngx_http_live_play_request_ctx_t* ss = NULL;

    ngx_rtmp_live_chunk_stream_t   *vcs = NULL;
    ngx_rtmp_live_chunk_stream_t   *acs = NULL;

    pctx = (ngx_http_rtmp_live_ctx_t*)ptrctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_http_rtmp_live_module);
    
    if (cscf == NULL || lacf == NULL || ctx == NULL || pctx == NULL) {
            return NGX_OK;
    }

    ss = pctx->http_ctx;
    cache = ctx->media_cache;

    vcs = &pctx->cs[0];
    acs = &pctx->cs[1];

    if (cache == NULL ||  ss == NULL || cache->busy_cache_head == NULL) {
        printf("http flv cache  is empty\n");
        return NGX_OK;
    }
    
    // 发送flv header
    if (ngx_http_flv_send_header(s, pctx) != NGX_OK) {
        printf("http flv : send header error\n");
        return NGX_OK;
    }
    
    printf("ngx_http_flv_media_data_cache_send send data\n");
    ngx_media_data_node_t * ln = cache->busy_cache_head;

    while (ln) {
        u_char mtype = 0;
        ngx_rtmp_live_chunk_stream_t * cs = NULL;
        ngx_uint_t   delta = 0;

        if (ln->mtype == NGX_RTMP_MSG_AUDIO) {
            mtype = HTTP_FLV_AUDIO_TAG;
            cs = acs;
        } else if (ln->mtype == NGX_RTMP_MSG_VIDEO) {
            mtype = HTTP_FLV_VIDEO_TAG;
            if (ln->key_frame == 1) {
                mtype = HTTP_FLV_VIDEO_KEY_FRAME_TAG;
            }
            cs = vcs;
        } else {
            continue;
        }
        
        rpkt = ln->cache_chain;
        delta = ln->delta;

        int mlen = 0;
        ngx_chain_t * l;
        for (l = rpkt; l; l = l->next) {
            mlen += (l->buf->last - l->buf->pos);
        }

        if (ngx_http_live_send_message(ss, rpkt, mtype, mlen, ln->mcpts, ln->delta) != NGX_OK) {
            ++pctx->ndropped;
            cs->dropped += delta;
                printf("***send packet error\n");
        }

        const char                     *type_s;
        type_s = (ln->mtype == NGX_RTMP_MSG_VIDEO ? "video" : "audio");
        cs->timestamp += delta;
        ss->current_time = cs->timestamp;
        printf("ngx_http_flv_media_data_cache_send send packet %s pts %d size %d\n",type_s,cs->timestamp,mlen);
        
        ln = ln->next;
        if (ln ==NULL)
            break;
    }
    return NGX_OK;
}


ngx_int_t 
ngx_media_data_cache_send(ngx_rtmp_session_t* s, void *ctx, ngx_int_t type)
{
    if (type == RTMP_PROTOCOL) {
        return ngx_rtmp_media_data_cache_send(s, ctx);
    } else if (type == HTTP_FLV_PROTOCOL) {
        return ngx_http_flv_media_data_cache_send(s, ctx);
    }
    return NGX_OK;
}


ngx_int_t ngx_media_data_cahce_clear(ngx_rtmp_session_t* s,ngx_int_t type)
{
    ngx_media_data_cache_t * cache = NULL;
    
    if(type == RTMP_PROTOCOL)
    {
        ngx_rtmp_live_app_conf_t       *lacf = NULL;
        ngx_rtmp_live_ctx_t            *rctx = NULL;
        ngx_rtmp_core_srv_conf_t       *cscf = NULL;
        lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
        rctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
        if (cscf == NULL || lacf == NULL ){
            return NGX_OK;
        }
        if(rctx)
        {
            cache = rctx->media_cache;
        }   
        if(cache && cache->busy_cache_head)
        {
            ngx_media_data_node_t * ln = cache->busy_cache_head;
            cache->busy_cache_head = ln->next;
            while(ln)
            {
                ngx_rtmp_free_shared_chain(cscf, ln->cache_chain);
                free_media_node(cache,ln);
                ln = NULL;

                if(cache->busy_cache_head)
                {
                    ln = cache->busy_cache_head;
                    cache->busy_cache_head = ln->next;
                }        
            }
            memset(cache,0,sizeof(ngx_media_data_node_t));
        }
    }
    else if (type == HTTP_FLV_PROTOCOL)
    {
        ngx_http_rtmp_live_app_conf_t       *lacf = NULL;
        ngx_http_rtmp_live_ctx_t            *rctx = NULL;

        lacf = ngx_rtmp_get_module_app_conf(s, ngx_http_rtmp_live_module);
        rctx = ngx_rtmp_get_module_ctx(s, ngx_http_rtmp_live_module);
        if (lacf == NULL ){
            return NGX_OK;
        }
        if(rctx)
        {
            cache = rctx->media_cache;
        }
        if(cache && cache->busy_cache_head)
        {
            ngx_media_data_node_t * ln = cache->busy_cache_head;
            cache->busy_cache_head = ln->next;
            while(ln)
            {
                ngx_http_flv_free_tag_mem(ln->cache_chain);
                free_media_node(cache,ln);
                ln = NULL;
                if(cache->busy_cache_head)
                {
                    ln = cache->busy_cache_head;
                    cache->busy_cache_head = ln->next;
                }        
            }
            memset(cache,0,sizeof(ngx_media_data_node_t));
        }
    }
    return NGX_OK;
}
