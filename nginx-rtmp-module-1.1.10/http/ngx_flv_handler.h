#ifndef  NGX_FLV_HANDLER_H
#define  NGX_FLV_HANDLER_H
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"

typedef short  short_2;
typedef int    int_4;

#define FLV_BIGENDIAN 1                                                                                   
#define FLV_LITTLEENDIAN 0   

#define NGX_STREAM_NOT_FIND 99999
#define NGX_STREAM_BACK_CC  999999

#define swicth_int(tag_data,len,pd) \
do{\
    unsigned char * ppc_tp = (unsigned char *)pd;\
    *(pd) = 0;\
    if(big_endian_test()){\
        memcpy(ppc_tp,tag_data,len);\
    }\
    else{\
        size_t n_tp = 0;\
        for(; n_tp < len;++n_tp){\
            ppc_tp[n_tp] = tag_data[len-n_tp-1];\
        }\
    }\
}while(0)

#define FLVFILE_COPYSTAMP_INT(nstamp,stamp)\
        nstamp = (unsigned char)stamp[3] << 24 | (unsigned char)stamp[0] << 16 | (unsigned char)stamp[1] << 8 | (unsigned char)stamp[2]

typedef struct ngx_flv_tag_header_s ngx_flv_tag_header_t;
typedef struct ngx_flv_amf_header_s ngx_flv_amf_header_t;
typedef struct ngx_flv_amf_array_node_s ngx_flv_amf_array_node_t;
typedef struct ngx_flv_amf_bool_array_node_s ngx_flv_amf_bool_array_node_t;
typedef struct ngx_flv_media_data_s ngx_flv_media_data_t;
typedef struct ngx_flv_video_avc_header_s ngx_flv_video_avc_header_t;
typedef struct ngx_flv_avc_config_header_s ngx_flv_avc_config_header_t;

struct ngx_flv_tag_header_s
{
	char  flv_tag_header_type;//video0x8 audio0x9  text12
	char  flv_tag_data_len[3];//tag data len 
	unsigned char  flv_tag_timestamp[4];//timestamp
	char  flv_tag_stream_id[3];//Always 0
};

struct ngx_flv_amf_header_s
{
    char amf1_type;//第一个amf 类型,一般是0x02 表示字符串
    short_2 str_len; //一般是0x0a
    char* ptr;//后面为数据，一般为onMetaData
    char amf2_type; //第二份amf2类型,一般是0x08 表示数组
    int_4 arr_size;//数组元素的个数
};

struct ngx_flv_amf_array_node_s
{
    char name_len[2]; //数组元素长度
    char name[256]; //元素名
    char type; //类型0x00
    double data; //数据
};

struct ngx_flv_amf_bool_array_node_s
{
    char name_len[2]; //数组元素长度
    char name[256]; //元素名
    char type; //类型0x01
    double data; //数据
};

struct ngx_flv_media_data_s
{
	int video_fps; //视频帧率
	int video_width; //视频宽
	int video_height;// 视频高
	int audio_samplerate;
    int audio_samplesize;
    unsigned int video_data_rate;
    unsigned int audio_data_rate;
};

struct ngx_flv_video_avc_header_s
{
	/*
		//ǰ��λΪFrame Type 
		1 = key frame (for AVC, a seekable frame)
		2 = inter frame (for AVC, a non-seekable frame)
		3 = disposable inter frame (H.263 only)
		4 = generated key frame (reserved for server use only)
		5 = video info/command frame 
		����λΪCodecID
		2 = Sorenson H.263
		3 = Screen video
		4 = On2 VP6
		5 = On2 VP6 with alpha channel
		6 = Screen video version 2
		7 = AVC 
	*/
	char Type;//��������Ϊ0x17Ϊ�ؼ��� 27Ϊһ��֡
	/*
		0 = AVC sequence header sps
		1 = AVC NALU
		2 = AVC end of sequence (lower level NALU sequence ender is 
		not required or supported)
	*/
	char AVCPacketType;
	/*
		IF AVCPacketType == 1
			Composition time offset 
		ELSE
			
	*/
	char compositiontime[3];
};

struct ngx_flv_avc_config_header_s
{
	//版本号 0x1
	char configurationVersion;

	//sps的第一个数据
	char AVCProfileIndication;

	//sps的第二个数据
	char profile_compatibility;

	//sps的第三个数据
	char AVCLevelIndication;

	//NALUnitLeght的长度 该值一般为ff
	//前6为保留 为111111
	char lenghtSizeMinusOne;

	//sps的个数
	//前3位保留 为111
	//后五位为sps的个数
	char numOfSequenceParameterSets;
	//sps_size + sps数据
	//sps_size为2个字节
	char * sps;
	int nspsLenght;

	//pps的个数
	char numOfPictureParameterSets;
	//pps_size + sps数据
	//pps_size为2个字节
	char * pps;
	int  nppsLenghth;
};


#define put_int_to_three_char(szThree,data) flv_put_num_to_buf(szThree,(const char*)&data,3)
#define put_double_to_eight_char(szEight,data) flv_put_num_to_buf(szEight,(const char*)&data,8)

#define s_wap16(s) ((((s) & 0xff) << 8) | (((s) >> 8) & 0xff))

#define s_wap32(l) (((l) >> 24) | \
(((l) & 0x00ff0000) >> 8)  | \
	(((l) & 0x0000ff00) << 8)  | \
	((l) << 24))

#define s_wap64(ll) (((ll) >> 56) |\
	(((ll) & 0x00ff000000000000) >> 40) |\
	(((ll) & 0x0000ff0000000000) >> 24) |\
	(((ll) & 0x000000ff00000000) >> 8)    |\
	(((ll) & 0x00000000ff000000) << 8)    |\
	(((ll) & 0x0000000000ff0000) << 24) |\
	(((ll) & 0x000000000000ff00) << 40) |\
	(((ll) << 56)))

#define big_endian_16(s) flv_big_endian_test() ? s : s_wap16(s)
#define little_endian_16(s) flv_big_endian_test() ? s_wap16(s) : s
#define big_endian_32(l) flv_big_endian_test() ? l : s_wap32(l)
#define little_endian_32(l) flv_big_endian_test() ? s_wap32(l) : l
#define big_endian_64(ll) flv_big_endian_test() ? ll : s_wap64(ll)
#define little_endian_64(ll) flv_big_endian_test() ? s_wap64(ll) : ll

#define FLVFILECOPYSTMP(stamp,TagStamp)\
{\
	long v = stamp;\
	TagStamp [2] = (unsigned char)(v & 0xFF);\
	v >>= 8;\
	TagStamp [1] = (unsigned char)(v & 0xFF);\
	v >>= 8;\
	TagStamp [0] = (unsigned char)(v & 0xFF);\
	v >>= 8;\
	TagStamp [3] = (unsigned char)(v & 0xFF);\
}


bool flv_big_endian_test();

void flv_put_num_to_buf(unsigned char szNum[],const char * psrc,int dstLenght);

bool ngx_flv_right_bigger(int left,int right);

int ngx_flv_mem_cp(void *dst,const void * src,int size);

int ngx_flv_write_amf_header(unsigned char * dst,int ndstlen,const  ngx_flv_amf_header_t amf_header);

int ngx_flv_creatm_databufNodeCommon(const char * szName,char nameLength[2],char* name );

int ngx_flv_createm_databufNode(const char * szName,double data,ngx_flv_amf_array_node_t * node);

int ngx_flv_createm_bdatabufNode(const char * szName,bool data, ngx_flv_amf_bool_array_node_t * node);

int ngx_flv_wrtitem_databufNode(unsigned char * buf,int nLength,const  ngx_flv_amf_array_node_t node);

int ngx_flv_wrtitem_bdatabufNode(unsigned char * buf,int nLength,const ngx_flv_amf_bool_array_node_t node);
#endif
