# 边缘节点新增配置相关描述

日志上报部分：
REPORT_POLL     日志上报频率
LOF_FILE        日志文件路径

HTTP 部分：
配置名称                      作用域            值                         描述  
http_live                    loc              on/off(默认off) 			 http-flv拉流开关
http_play_domain             loc			  on/off(默认off)             http播放地址必须带上域名
live_md5_check               loc              on/off(默认off)             md5鉴权开关，如果设置为on怎开启MD5鉴权，通过才能够播放
md5_key                      loc              字符串(默认为“”)			 MD5 鉴权的秘钥
http_live_app                loc              字符串(默认为“”)             播放请求对应的rtmp的 app的名称，如果设置为空就去http播放url中的uri第一级字符串。
http_send_timeout            loc              数值(默认10s，单位秒）        发送数据写事件的超时时间
send_http_header_timeout     loc              数值(默认值5s,单位秒)         发送http 请求响应头的超时时间，如果时间到了还没发送头信息就关闭连接
http_send_chunk_size         loc              数值(默认值4096，单位字节)     每次发送数据块的大小
http_send_max_chunk_count    loc              数值(默认值256)               一次最多发送多少块数据和http_send_chunk_size一起使用可以控制流量
http_idle_play_timeout       loc              数值(默认值0,单位秒)           请求连接多少秒内没有数据往来，怎认为是空闲连接主动踢掉连接，值为0时表示不开启次功能
http_play_cache_on           loc              on/off(默认off)              连接开启自动缓存buffer标记
http_play_cahce_time_duration loc             数值(默认值0,单位秒)           连接对应的发送缓冲队列最大缓冲时长，为0时表示次标记无效
http_play_cahce_frame_num     loc             数值(默认值1024)              连接对应的发送缓冲队列最大缓冲多少包数据和http_play_cahce_time_duration可以同时设置，只要一个条件满足都开始丢帧
http_on_play                  loc             字符串(默认为“”)               获取rtmp或者http回源地址的接口地址
relay_secret_id               loc             字符串(默认为“”)               获取回源地址鉴权对应的ID
relay_secret_key              loc             字符串(默认为“”)               获取回源地址鉴权对应的秘钥
relay_md5_on                  loc             on/off(默认off)               获取回源地址是否需要鉴权
notify_method                 loc             字符串(默认为“get”)            获取回源地址的http请求方法 是GET或POST
rtmp_sever_port               loc             数值(默认1935)                 对应的RTMP的server的哪一个域
http_netcall_timeout          loc             数值(默认值5,单位秒)            获取回源地址的超时时间，如果时间到了还没有请求返回则认为回源失败
rtmp_back_source_addr_param_name loc          字符串(默认为“”)               http播放地址也可以自带rtmp回源地址的参数名称，如果带了这个参数就不触发接口获取回源地址
http_back_source_addr_param_name loc          字符串(默认为“”)               http播放地址也可以自带rtmp回源地址的参数名称或302跳转地，如果带了这个参数就不触发接口获取回源地址
reconnect_count_before_302     loc            数值(默认值3 单位秒)            如果流频繁回源的次数超过设置的值后则直接302跳转到原地址拉流

RTMP 部分：
hdl                          app              on/off(默认off)               rtmp转http-flv直播的开关
http_live_idle_streams       app              on/off(默认on)                http-flv直播中上行断开是否立马断开所有的下行链接的标志，设置为on表示不立马断开,等等链接主动断开或超时
cache_gop                    app              on/off(默认off)               秒开缓存的开启的开关
cache_gop_duration           app              数值(默认值0,单位秒)            秒开缓存最大缓冲多长时间
cache_gop_num                app              数值(默认值0)                  秒开缓存最大缓冲多少个gop
idle_up_stream_destory       srv              数值(默认值0，单位秒)           冷热流功能的开关，如果不为0秒呢流没有下行的拉流链接则认为是冷流主动断开上行链接
rtmp_log_poll                app/srv/main     数值(默认值5 ,单位秒)           推流或拉流监控流状态的日志周期时间
rtmp_log                     app/srv/main     字符串(默认为“”)                自定义日志输出路径

配置模板(nginx.conf)
worker_processes  1;

events {
     worker_connections  1024;
 }

rtmp{
	rtmp_log /Users/liwu/Desktop/workspace/server/ABSrcSite/ForwardCacheServer/sbin/logs/rtmp.log info;
	server{
	        listen 1935;
			chunk_size 1024;
			out_queue 1024;
			idle_up_stream_destory 120;
			application momo{
				live on;
				hdl  on;
				drop_idle_publisher 10s;
				cache_gop on;
				cache_gop_num 3;
			}
		}
	}

http{
	include       mime.types;
	default_type  application/octet-stream;
	sendfile        on;
	keepalive_timeout  65;

	server {
        listen       8008;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / { 
            root   html;
            index  index.html index.htm;
        }   
       
        location /myapp {
            http_live on; 
            #live_md5_check on; 
			#md5_key 124324;
            reconnect_count_before_302 3;
            http_live_app momo;
            http_idle_play_timeout 10; 
            http_play_cache_on on; 
            http_play_cahce_time_duration 5s; 
            http_send_max_chunk_count  1;  

            http_on_play http://127.0.0.1:8008/backsource;
            relay_secret_id xxxxx;
            relay_secret_key xxxxx;
            relay_md5_on on; 
            notify_method GET;
        }   
       
        location /backsource {
            proxy_pass https://live-api.immomo.com/ext/cdn/backtosource;
        }  
    }

}



