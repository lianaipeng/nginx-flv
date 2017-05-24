
#include "ngx_rtmp_edge_log.h"
#include "ngx_rtmp_codec_module.h"
#include <stdarg.h> 
#include <stdio.h> 

char ngx_edge_type[2][32] = {
    {"rtmp"},
    {"http-flv"}
};

void ngx_printf_log(char* module,char* function,char* action, ...)
{
#if NGX_PRINTF_LOG
    if(module  && function  && action )
    {
         char buffer[1024]={0};
         va_list arg;
         va_start (arg, action);
         vsnprintf(buffer,1024, action, arg);
         va_end (arg);
         printf("module: %s function: %s action: %s \n",module,function,buffer);
    }
#endif
}

void 
ngx_rtmp_edge_log(ngx_uint_t proType, ngx_uint_t logType, void *ss, ngx_uint_t current_ts)
{
    ngx_rtmp_session_t                      *s;
    ngx_http_live_play_request_ctx_t        *pr;
    ngx_http_live_netcall_session_t         *cs;
    ngx_rtmp_codec_ctx_t                    *codec;
    char                                    *szformat = NULL;
    
    if (ss == NULL )
        return;
    
    switch (logType) {
        case NGX_EDGE_PULL_START:
            szformat = "EDGE{\"_type\":\"v2.edgePullStart\",\"timestamp\":%l,\"session\":\"%s\",\"clientIP\":\"%V\",\"serverIP\":\"%V\",\"host\":\"%V\",\"name\":\"%V\",\"protocolType\":\"%s\",\"body\":{\"responseTime\":%l,\"pullUrl\":\"%V\"}}EDGE";
            if (proType == NGX_EDGE_RTMP) {
                s = (ngx_rtmp_session_t *)ss;
                if ( global_log == NULL && s->connection && s->connection->log) {
                    global_log = s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, &s->uuid, 
                        &s->client_ip, &s->server_ip, &s->host, &s->name, 
                        ngx_edge_type[proType], 0, &s->pull_url);
            } else if ( proType == NGX_EDGE_HTTP ){
                pr = (ngx_http_live_play_request_ctx_t *)ss;
                if ( global_log == NULL && pr->s && pr->s->connection && pr->s->connection->log) {
                    global_log = pr->s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, pr->uuid, 
                        &pr->client_ip, &pr->server_ip, &pr->host, &pr->stream, 
                        ngx_edge_type[proType], pr->current_ts-pr->request_ts, &pr->pull_url);
            } else { 
                return;
            } 
            break;
        case NGX_EDGE_PULL_WATCH:
            szformat = "EDGE{\"_type\":\"v2.edgePullWatch\",\"timestamp\":%l,\"session\":\"%s\",\"clientIP\":\"%V\",\"serverIP\":\"%V\",\"host\":\"%V\",\"name\":\"%V\",\"protocolType\":\"%s\",\"body\":{\"pullUrl\":\"%V\",\"pts\":%l,\"videoSize\":%l,\"audioSize\":%l,\"delay\":%l,\"sendFrame\":%l,\"dropVideoFrame\":%l,\"cacheVideoFrame\":%l}}EDGE";
            if (proType == NGX_EDGE_RTMP) {
                s = (ngx_rtmp_session_t *)ss;
                if ( global_log == NULL && s->connection && s->connection->log ) {
                    global_log = s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, s->uuid, 
                        &s->client_ip, &s->server_ip, &s->host, &s->name, 
                        ngx_edge_type[proType], &s->pull_url, s->stream_ts,   
                        s->recv_video_size - s->lrecv_video_size, 
                        s->recv_audio_size - s->lrecv_audio_size, s->delta, 
                        s->recv_video_frame - s->lrecv_video_frame, 0, 0);
            } else if (proType == NGX_EDGE_HTTP ) {
                pr = (ngx_http_live_play_request_ctx_t *)ss;
                if ( global_log == NULL && pr->s && pr->s->connection && pr->s->connection->log) {
                    global_log = pr->s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, pr->uuid, 
                        &pr->client_ip, &pr->server_ip, &pr->host, &pr->stream, 
                        ngx_edge_type[proType], &pr->pull_url, pr->stream_ts, 
                        pr->recv_video_size - pr->lrecv_video_size, 
                        pr->recv_audio_size - pr->lrecv_audio_size, pr->delta, 
                        pr->recv_video_frame - pr->lrecv_video_frame, 
                        pr->dropVideoFrame, pr->cacheVideoFrame);
            } else {
                return;
            } 
            break;
        case NGX_EDGE_PULL_STOP:
            szformat = "EDGE{\"_type\":\"v2.edgePullStop\",\"timestamp\":%l,\"session\":\"%s\",\"clientIP\":\"%V\",\"serverIP\":\"%V\",\"host\":\"%V\",\"name\":\"%V\",\"protocolType\":\"%s\",\"body\":{\"pullUrl\":\"%V\",\"duration\":%l,\"statusCode\":%l,\"videoSize\":%l,\"audioSize\":%l,\"allDropFrame\":%l}}EDGE";
            if (proType == NGX_EDGE_RTMP) {
                s = (ngx_rtmp_session_t *)ss;
                if ( global_log == NULL && s->connection && s->connection->log ) {
                    global_log = s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, s->uuid,
                        &s->client_ip, &s->server_ip, &s->host, &s->name, 
                        ngx_edge_type[proType], &s->pull_url, 0, 
                        s->status_code, s->recv_video_size, s->recv_audio_size, s->dropVideoFrame);
            } else if (proType == NGX_EDGE_HTTP) {
                pr = (ngx_http_live_play_request_ctx_t *)ss;
                if ( global_log == NULL && pr->s && pr->s->connection && pr->s->connection->log) {
                    global_log = pr->s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, pr->uuid, 
                        &pr->client_ip, &pr->server_ip, &pr->host, &pr->stream, 
                        ngx_edge_type[proType], &pr->pull_url, pr->current_ts-pr->request_ts, 
                        pr->status_code, pr->recv_video_size, 
                        pr->recv_audio_size, pr->dropVideoFrame);
            } else {
                return;
            }
            break;
        case NGX_EDGE_PUSH_START:
            szformat = "EDGE{\"_type\":\"v2.edgePushStart\",\"timestamp\":%l,\"session\":\"%s\",\"clientIP\":\"%V\",\"serverIP\":\"%V\",\"host\":\"%V\",\"name\":\"%V\",\"protocolType\":\"%s\",\"body\":{\"firstRecvTime\":%l,\"url\":\"%V\",\"vFormat\":\"h264\",\"vFps\":%l,\"vBitRate\":%l,\"aFormat\":\"aac\",\"aChannel\":%l,\"aSamplerate\":%l}}EDGE";
            if (proType == NGX_EDGE_RTMP) {
                s = (ngx_rtmp_session_t *)ss;
                if ( global_log == NULL && s->connection && s->connection->log ) {
                    global_log = s->connection->log;
                }
                codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, s->uuid, 
                        &s->client_ip, &s->server_ip, &s->host, &s->name, 
                        ngx_edge_type[proType], current_ts, &s->pull_url, 
                        codec->frame_rate, codec->video_data_rate, 
                        codec->audio_channels, codec->sample_rate);
            } else {
                return;
            }
            break;
        case NGX_EDGE_PUSH_WATCH:
            szformat = "EDGE{\"_type\":\"v2.edgePushWatch\",\"timestamp\":%l,\"session\":\"%s\",\"clientIP\":\"%V\",\"serverIP\":\"%V\",\"host\":\"%V\",\"name\":\"%V\",\"protocolType\":\"%s\",\"body\":{\"recvVideoSize\":%l,\"recvAudioSize\":%l,\"recvVideoFrame\":%l,\"sendVideoSize\":%l,\"sendAudioSize\":%l}}EDGE";
            if (proType == NGX_EDGE_RTMP) {
                s = (ngx_rtmp_session_t *)ss;
                if ( global_log == NULL && s->connection && s->connection->log ) {
                    global_log = s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, s->uuid, 
                        &s->client_ip, &s->server_ip, &s->host, &s->name, ngx_edge_type[proType],
                        s->recv_video_size - s->lrecv_video_size, 
                        s->recv_audio_size - s->lrecv_audio_size, 
                        s->recv_video_frame - s->lrecv_video_frame, 
                        s->send_video_size - s->lsend_video_size, 
                        s->send_audio_size - s->lsend_audio_size);
            } else {
                return;
            }
            break;
        case NGX_EDGE_PUSH_STOP:
            szformat = "EDGE{\"_type\":\"v2.edgePushStop\",\"timestamp\":%l,\"session\":\"%s\",\"clientIP\":\"%V\",\"serverIP\":\"%V\",\"host\":\"%V\",\"name\":\"%V\",\"protocolType\":\"%s\",\"body\":{\"statusCode\":%l,\"recvVideoSize\":%l,\"recvAudioSize\":%l,\"recvVideoFrame\":%l,\"sendVideoSize\":%l,\"sendAudioSize\":%l}}EDGE";
            if (proType == NGX_EDGE_RTMP) {
                s = (ngx_rtmp_session_t *)ss;
                if ( global_log == NULL && s->connection && s->connection->log ) {
                    global_log = s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, s->uuid, 
                        &s->client_ip, &s->server_ip, &s->host, &s->name, ngx_edge_type[proType], s->status_code, 
                        s->recv_video_size, s->recv_audio_size, s->recv_video_frame, 
                        s->send_video_size, s->send_audio_size);
            } else {
                return;
            }
            break;
        case NGX_EDGE_BUFFER_START:
            szformat = "EDGE{\"_type\":\"v2.edgeBufferStart\",\"timestamp\":%l,\"session\":\"%s\",\"clientIP\":\"%V\",\"serverIP\":\"%V\",\"host\":\"%V\",\"name\":\"%V\",\"protocolType\":\"%s\",\"body\":{\"cacheVideoFrame\":%l,\"cacheDuration\":%l}}EDGE";
            if (proType == NGX_EDGE_HTTP) {
                pr = (ngx_http_live_play_request_ctx_t *)ss;
                if ( global_log == NULL && pr->s && pr->s->connection && pr->s->connection->log) {
                    global_log = pr->s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, pr->uuid, 
                        &pr->client_ip, &pr->server_ip, &pr->host, &pr->stream, 
                        ngx_edge_type[proType], pr->drop_vframe_num, pr->drop_vduration);
                printf("####################### NGX_EDGE_BUFFER_START LOG\n");
            } else {
                return;
            }
            break;
        case NGX_EDGE_BUFFER_STOP:
            szformat = "EDGE{\"_type\":\"v2.edgeBufferStop\",\"timestamp\":%l,\"session\":\"%s\",\"clientIP\":\"%V\",\"serverIP\":\"%V\",\"host\":\"%V\",\"name\":\"%V\",\"protocolType\":\"%s\",\"body\":{\"dropVideoSize\":%l,\"dorpAudioSize\":%l,\"dropVideoFrame\":%l,\"duration\":%l}}EDGE";
            if (proType == NGX_EDGE_HTTP) {
                pr = (ngx_http_live_play_request_ctx_t *)ss;
                if ( global_log == NULL && pr->s && pr->s->connection && pr->s->connection->log) {
                    global_log = pr->s->connection->log;
                }
                ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, pr->uuid, 
                        &pr->client_ip, &pr->server_ip, &pr->host, &pr->stream, 
                        ngx_edge_type[proType], pr->drop_video_size, pr->drop_audio_size, pr->drop_vframe_num, pr->drop_vduration);
            } else {
                return; 
            }
            break;
        case NGX_EDGE_BACK_SOURCE:
            szformat = "EDGE{\"_type\":\"v2.edgeBackSource\",\"timestamp\":%l,\"statusCode\":%l,\"rtmp_pull_url\":\"%V\",\"http_pull_url\":\"%V\",\"duration\":%l}EDGE";
            if (proType == NGX_EDGE_HTTP) {
                cs = (ngx_http_live_netcall_session_t *)ss;
                if (global_log == NULL && cs->session && cs->session->connection && cs->session->connection->log ){
                    global_log = cs->session->connection->log;
                }
                if (cs && cs->ctx) { 
                    ngx_log_error(NGX_LOG_INFO, global_log, 0, szformat, current_ts, cs->status_code, 
                            &cs->ctx->rtmp_pull_url, &cs->ctx->http_pull_url, current_ts-cs->netcall_ts);
                }
            } else {
                return;
            }
            break;
    }
    return;
}
