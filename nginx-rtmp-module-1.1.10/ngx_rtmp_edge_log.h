
#ifndef _NGX_RTMP_EDGE_MONITOR_H_INCLUDED_
#define _NGX_RTMP_EDGE_MONITOR_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_rtmp.h>
#include "http/ngx_http_live_play_module.h"
#include "http/ngx_http_live_play_relay_module.h"

enum ngx_status_code {
    ngx_normal_close = 0,
    ngx_unknown_close_err = 1, // 未知
    ngx_rtmp_connect_err = 2,
    ngx_rtmp_handshake_done_err = 3,
    ngx_rtmp_handshake_recv_timedout = 4,
    ngx_rtmp_handshake_recv_data_err = 5,
    ngx_rtmp_handshake_recv_read_err = 6,
    ngx_rtmp_handshake_parsing_challenge_err = 7,
    ngx_rtmp_handshake_create_challenge_err = 8,
    ngx_rtmp_handshake_response_err = 9,
    ngx_rtmp_handshake_send_timedout = 10,
    ngx_rtmp_handshake_send_data_err = 11,
    ngx_rtmp_handshake_send_write_err = 12,
    ngx_rtmp_handshake_write_event_err = 13,

    ngx_rtmp_handler_in_buf_alloc_err = 14,
    ngx_rtmp_handler_recv_data_err = 15,
    ngx_rtmp_handler_recv_read_err = 16,
    ngx_rtmp_handler_send_ack_err = 17,
    ngx_rtmp_handler_in_chunk_too_big = 18,
    ngx_rtmp_handler_message_too_big = 19,
    ngx_rtmp_handler_send_timedout = 20,
    ngx_rtmp_handler_send_write_err= 21,
    ngx_rtmp_handler_out_chunk_too_big = 22,


    ngx_rtmp_live_idle_publisher = 23,
    ngx_rtmp_live_send_message_err = 24,
    ngx_rtmp_live_no_stream_err = 25,
    ngx_rtmp_live_no_publisher_err = 26,
    ngx_rtmp_live_mandatory_err = 27,
    ngx_rtmp_live_idel_stream = 28,

    ngx_rtmp_relay_create_publish_err = 29,
    ngx_rtmp_relay_publish_disconnect_empty = 30,
    ngx_rtmp_relay_play_disconnect_empty = 31,

    ngx_rtmp_netcall_err = 32,

    ngx_http_live_recv_handler_err = 33,
    ngx_http_live_write_handler_err = 34,
    ngx_http_live_client_timedout = 35,
    ngx_http_live_write_event_err = 36,
    ngx_http_live_send_data_err = 37,
    ngx_http_live_parse_play_uri_err = 38,
    ngx_http_live_parse_play_arg_err = 39,
    ngx_http_live_status_403_err = 40,
    ngx_http_live_stream_rewait_err = 41,

    ngx_http_live_not_allowed = 42,
    ngx_http_live_status_302_err = 43,
    ngx_http_live_send_header_timedout= 44,
    ngx_http_live_send_data_timedout = 45,

    ngx_http_relay_netcall_timedout = 46,
    ngx_http_relay_sink_err = 47,
    ngx_http_relay_alloc_chain_err = 48,
    ngx_http_relay_create_buf_err = 49,
    ngx_http_relay_recv_data_err = 50,
    ngx_http_relay_recv_filter_err = 51,
    ngx_http_relay_read_event_err = 52,
    ngx_http_relay_send_timedout = 53,
    ngx_http_relay_send_chain_err = 54,
    ngx_http_relay_send_write_err = 55,
    ngx_http_relay_play_close   = 56,
    ngx_http_cut_play_by_drop = 57,
    ngx_http_cut_by_cache_full = 58,
    ngx_http_send_http_header_error  = 59,
    ngx_http_request_uri_err = 60,
    ngx_http_request_param_err = 61,
    ngx_rtmp_status_code_count
};

enum ngx_rtmp_log_type {
    NGX_EDGE_PULL_START = 0,
    NGX_EDGE_PULL_STOP,
    NGX_EDGE_PULL_WATCH,
    NGX_EDGE_BUFFER_START,
    NGX_EDGE_BUFFER_STOP,
    NGX_EDGE_PUSH_START,
    NGX_EDGE_PUSH_STOP,
    NGX_EDGE_PUSH_WATCH,
    NGX_EDGE_BACK_SOURCE,
    NGX_EDGE_TYPE_COUNT,
};

enum ngx_rtmp_edge_protocol_type {
    NGX_EDGE_RTMP,
    NGX_EDGE_HTTP
};

#define NGX_PRINTF_LOG 0


void ngx_rtmp_edge_log(ngx_uint_t proType, ngx_uint_t logType, void *ss, ngx_uint_t current_ts);

void ngx_printf_log(char* module,char* function,char* action, ...);
#endif
