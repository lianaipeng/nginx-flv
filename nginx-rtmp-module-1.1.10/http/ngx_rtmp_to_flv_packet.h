#ifndef NGX_RTMP_TO_FLV_PACKET_H
#define NGX_RTMP_TO_FLV_PACKET_H

#include "ngx_flv_handler.h"

ngx_int_t ngx_http_flv_prepare_message(ngx_rtmp_header_t *h,ngx_chain_t* in, ngx_chain_t *out,unsigned int * out_size);


ngx_chain_t* ngx_http_flv_perpare_meta_header(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h
                                        ,ngx_chain_t *out);  //header =  flv header tag + mediadata tag

ngx_chain_t* ngx_http_flv_perpare_video_header(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h
                                        ,ngx_chain_t *out);

ngx_chain_t* ngx_http_flv_perpare_audio_header(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h
                                        ,ngx_chain_t *out);

ngx_chain_t*  ngx_http_flv_base_alloc_tag_mem(size_t mem_size);

ngx_chain_t*  ngx_http_flv_alloc_tag_mem(ngx_chain_t* in);

ngx_chain_t * ngx_http_flv_copy_tag_mem(ngx_chain_t* in);

void ngx_http_flv_free_tag_mem(ngx_chain_t* in);

ngx_int_t ngx_http_flv_perpare_header(ngx_rtmp_session_t *s,void * ctx,ngx_rtmp_header_t *h); //header =  flv header tag + mediadata tag + aac_tag +avc_tag

#endif