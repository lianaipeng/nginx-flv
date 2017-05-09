#ifndef NGX_HTTP_RTMP_LIVE_MODULE_H
#define NGX_HTTP_RTMP_LIVE_MODULE_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"
#include "ngx_http_live_play_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_media_data_cache.h"

typedef struct ngx_http_rtmp_live_ctx_s ngx_http_rtmp_live_ctx_t;
typedef struct ngx_http_rtmp_live_stream_s ngx_http_rtmp_live_stream_t;
typedef struct ngx_http_rtmp_live_app_conf_s ngx_http_rtmp_live_app_conf_t;

struct ngx_http_rtmp_live_ctx_s{
    ngx_rtmp_session_t                  *s;
    ngx_uint_t                          ndropped;
    ngx_str_t                           name;          // stream name 
    ngx_pool_t                          *pool;      //for frame
    ngx_int_t                           publishing;
    ngx_http_live_play_request_ctx_t    *http_ctx;
    ngx_http_rtmp_live_stream_t          *stream;

    ngx_http_rtmp_live_app_conf_t*      conf;

    ngx_uint_t                          meta_version;
    ngx_rtmp_live_chunk_stream_t        cs[2];
    ngx_http_rtmp_live_ctx_t            *next; 

    ngx_media_data_cache_t              *media_cache;
};

typedef struct {
    int fill;//填充数满

}ngx_http_rtmp_live_srv_conf_t;


struct ngx_http_rtmp_live_stream_s {
    u_char                              name[NGX_RTMP_MAX_NAME];
    ngx_http_rtmp_live_stream_t             *next;
    ngx_http_rtmp_live_ctx_t                *ctx;
    void                                 *relay_ctx;

    ngx_rtmp_bandwidth_t                bw_in;
    ngx_rtmp_bandwidth_t                bw_in_audio;
    ngx_rtmp_bandwidth_t                bw_in_video;
    ngx_rtmp_bandwidth_t                bw_out;
    ngx_rtmp_bandwidth_t                bw_out_audio;
    ngx_rtmp_bandwidth_t                bw_out_video;
    unsigned  int                       publishing;
    unsigned  int                       streaming;

    unsigned int                       tag_buf_len;
    unsigned int                       avc_tag_size;
    ngx_chain_t*                       avc_conf_tag;
    unsigned int                       aac_tag_size;
    ngx_chain_t*                       aac_conf_tag;
    unsigned int                       meta_tag_size;
    ngx_chain_t*                       meta_conf_tag; 
    u_char                             flv_header_update;

    ngx_uint_t                          width;
    ngx_uint_t                          height;
    ngx_uint_t                          frame_rate;
    ngx_uint_t                          video_data_rate;
    ngx_uint_t                          video_codec_id;

    ngx_uint_t                          audio_codec_id;
    ngx_uint_t                          sample_rate;    /* 5512, 11025, 22050, 44100 */
    ngx_uint_t                          sample_size;    /* 1=8bit, 2=16bit */
    ngx_uint_t                          audio_channels; /* 1, 2 */
};

 struct ngx_http_rtmp_live_app_conf_s{
    ngx_int_t                         nbuckets;
    ngx_http_rtmp_live_stream_t       **streams;
    ngx_http_rtmp_live_stream_t       *free_streams;

    ngx_pool_t                          *pool;      //for frame
    ngx_flag_t                          hdl;
    ngx_flag_t                          http_idle_streams;
    ngx_str_t                           server;
} ;

extern ngx_module_t  ngx_http_rtmp_live_module;

ngx_int_t ngx_http_rtmp_live_play(void* http_ctx);

ngx_int_t ngx_http_rtmp_live_close_play_stream(void* http_ctx);
#endif