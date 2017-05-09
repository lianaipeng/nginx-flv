#ifndef NGX_MEDIA_DATA_CACHE_H
#define NGX_MEDIA_DATA_CACHE_H
#include "ngx_rtmp.h"

#define  RTMP_PROTOCOL 0
#define  HTTP_FLV_PROTOCOL 1

typedef struct ngx_media_data_node_s ngx_media_data_node_t;

struct ngx_media_data_node_s{
    ngx_int_t       key_frame; //gop 第一帧
    ngx_int_t       mtype; //数据类型 ，音频 or 视频
    ngx_uint_t      mcpts;       //当前时间戳
    ngx_uint_t      mlpts;   //上一帧时间戳
    ngx_uint_t      delta;  //时间间隔
    ngx_uint_t      prio;            //优先级
    ngx_chain_t *   cache_chain;    //缓存的数据
    ngx_media_data_node_t * next;
};

typedef struct{
    ngx_rtmp_session_t *s;
    ngx_uint_t      cache_duration;
    ngx_int_t       cache_frame_num;
    ngx_uint_t      video_cache_duration;
    ngx_int_t       video_cache_frame_num;
    ngx_uint_t      audio_cache_duration;
    ngx_int_t       audio_cache_frame_num;
    ngx_uint_t      cache_gop_num;

    ngx_chain_t           *avc_header;
    ngx_chain_t           *aac_header;
    
    ngx_media_data_node_t * busy_cache_head;
    ngx_media_data_node_t * busy_cache_tail;
    ngx_media_data_node_t * free_node_list;
}ngx_media_data_cache_t; 


ngx_chain_t* ngx_media_data_cache_write(ngx_rtmp_session_t* s, ngx_rtmp_header_t *h,
                                        ngx_chain_t* in,ngx_rtmp_header_t *ch,
                                        ngx_rtmp_header_t *lh,ngx_int_t type);

ngx_int_t 
ngx_media_data_cache_send(ngx_rtmp_session_t *s, void *ctx, ngx_int_t type);

ngx_int_t ngx_media_data_cahce_clear(ngx_rtmp_session_t* s,ngx_int_t type);

ngx_int_t ngx_http_flv_send_header(ngx_rtmp_session_t* s,void* pctx);

#endif
