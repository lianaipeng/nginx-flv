#include "ngx_rtmp_to_flv_packet.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_http_rtmp_live_module.h"

ngx_chain_t*  ngx_http_flv_base_alloc_tag_mem(size_t mem_size)
{
    u_char * p = NULL;
    ngx_chain_t                *out;
    ngx_buf_t                  *b;

    unsigned int tag_size = 128;
    unsigned int struct_size = sizeof(ngx_chain_t)+sizeof(ngx_buf_t);
    unsigned int size = mem_size + struct_size + tag_size;
    p = (u_char*)malloc(size);

    if (p == NULL) {
        return NULL;
    }

    out = (ngx_chain_t *)p;
    p += sizeof(ngx_chain_t);

    out->buf = (ngx_buf_t *)p;
    p += sizeof(ngx_buf_t);

    out->buf->start = p;
    out->buf->end = p + (size - struct_size);

    out->next = NULL;
    b = out->buf;
    b->pos = b->last = p;
    b->memory = 1;
    return out;
}

ngx_chain_t*  ngx_http_flv_alloc_tag_mem(ngx_chain_t* in)
{
    size_t mlen = 0;
    ngx_chain_t * l;
    for(l = in; l; l = l->next) {
        mlen += (l->buf->last - l->buf->pos);
    }
    return ngx_http_flv_base_alloc_tag_mem(mlen);
}

ngx_chain_t * ngx_http_flv_copy_tag_mem(ngx_chain_t* in)
{
    ngx_chain_t * l = ngx_http_flv_alloc_tag_mem(in);
    if(l)
    {
        int mlen = in->buf->last - in->buf->pos;
        memcpy(l->buf->pos,in->buf->pos,mlen);
        l->buf->last = l->buf->pos + mlen;
    }
    return l;
}

void ngx_http_flv_free_tag_mem(ngx_chain_t* in)
{
    if(in)
    {
        u_char* p = (u_char*)in;
        free(p);
        in = NULL;
    }
}

ngx_int_t   
ngx_perpare_flv_header(u_char* flv_header, int has_video, int has_audio, unsigned int* data_size)
{
    if(flv_header == NULL)
        return NGX_ERROR;
    int i = 0;
    flv_header[i++] = 0x46; //'F'
    flv_header[i++] = 0x4c; //'L'
    flv_header[i++] = 0x56; //'V'
    flv_header[i++] = 0x1; //version 1
    if( has_video && has_audio) //type
        flv_header[i++] = 0x05;
    else 
        flv_header[i++] = 0x01;
    flv_header[i++] = 0x00;
    flv_header[i++] = 0x00;
    flv_header[i++] = 0x00;
    flv_header[i++] = 0x09; /* header size */

    flv_header[i++] = 0x00;
    flv_header[i++] = 0x00;
    flv_header[i++] = 0x00;
    flv_header[i++] = 0x00; //tag0 size
    *data_size = i;
    return NGX_OK;
}

ngx_int_t ngx_prepare_flv_media_data(u_char* buf,unsigned int buf_len,int need_duration_and_filesize,
        int has_video,int has_audio,unsigned int* duration_pos,unsigned int * file_size_pos
        ,ngx_flv_media_data_t meta,unsigned int* data_size)
{
    if(buf == NULL)
        return NGX_ERROR;
        
    unsigned int meta_size = 0;
	ngx_flv_tag_header_t tag_header;
    memset(&tag_header,0,sizeof(ngx_flv_tag_header_t));

	int meta_data_pos = sizeof(tag_header.flv_tag_header_type);

	tag_header.flv_tag_header_type = 0x12;//½Å±¾ ¼ÇÂ¼ÊÓÆµÐÅÏ¢

    if(ngx_flv_right_bigger(buf_len,sizeof(ngx_flv_tag_header_t) + 4))
		return NGX_ERROR;
        
	meta_size += ngx_flv_mem_cp(buf,&tag_header,sizeof(ngx_flv_tag_header_t));
	int last_size = meta_size;

	ngx_flv_amf_header_t amf_header;
	amf_header.amf1_type = 0x12;
	amf_header.str_len = 0x0a;
	amf_header.ptr = "onMetaData";
	amf_header.amf2_type = 0x08;	
	if(need_duration_and_filesize)
		amf_header.arr_size = 0xd;
	else
		amf_header.arr_size = 0xb;
    
    if(!has_audio)
        amf_header.arr_size -= 2;//audiocodecid, sampleate , audiodatarate
    
    if(has_video)
        amf_header.arr_size -= 5;//width,height,videocodecid,videorate,framerate

	meta_size += ngx_flv_write_amf_header(buf+meta_size,buf_len-meta_size,amf_header);

    ngx_flv_amf_array_node_t node;
	if(need_duration_and_filesize)
	{
		ngx_flv_createm_databufNode("duration",0.0,&node);
		meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);
		*duration_pos = (meta_size - sizeof(double));
	}

	ngx_flv_amf_bool_array_node_t bnode;
	ngx_flv_createm_bdatabufNode("hasVideo",has_video,&bnode);
	meta_size += ngx_flv_wrtitem_bdatabufNode(buf+meta_size,buf_len-meta_size,bnode);

	ngx_flv_createm_bdatabufNode("hasAudio",has_audio,&bnode);
	meta_size += ngx_flv_wrtitem_bdatabufNode(buf+meta_size,buf_len-meta_size,bnode);

	ngx_flv_createm_bdatabufNode("hasMetadata",1,&bnode);
	meta_size += ngx_flv_wrtitem_bdatabufNode(buf+meta_size,buf_len-meta_size,bnode);

    if(has_video)
    {
	    ngx_flv_createm_databufNode("width",meta.video_width,&node);
	    meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);
	
	    ngx_flv_createm_databufNode("height",meta.video_height,&node);
	    meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);
	
	    ngx_flv_createm_databufNode("framerate",meta.video_fps,&node);
	    meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);

	    ngx_flv_createm_databufNode("videodatarate",meta.video_data_rate,&node);
	    meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);

        ngx_flv_createm_databufNode("videocodecid",0x7,&node);
	    meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);
    }

    if(need_duration_and_filesize)
	{
		ngx_flv_createm_databufNode("filesize",0,&node);
		meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);
		*file_size_pos = (meta_size - sizeof(double));
	}

    if(has_audio)
    {
	    ngx_flv_createm_databufNode("audiocodecid",0xA,&node);
	    meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);

	    ngx_flv_createm_databufNode("audiosamplerate ",meta.audio_samplerate,&node);
	    meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);

	    ngx_flv_createm_databufNode("audiosamplesize ",meta.audio_samplesize,&node);
	    meta_size += ngx_flv_wrtitem_databufNode(buf+meta_size,buf_len-meta_size,node);
    }

    buf[meta_size++] = 0x09;//end

	int meta_data_size = meta_size - last_size;
	put_int_to_three_char(buf+meta_data_pos,meta_data_size);

	unsigned int meta_tag_size = meta_data_size + sizeof(ngx_flv_tag_header_t);

	meta_tag_size = big_endian_32(meta_tag_size);
	if(ngx_flv_right_bigger(buf_len-meta_size,sizeof(meta_tag_size)))
		return NGX_ERROR;

	meta_size += ngx_flv_mem_cp(buf+meta_size,&meta_tag_size,sizeof(meta_tag_size));

    *data_size = meta_size;

    return NGX_OK;
}

int  ngx_prepare_flv_avc_header_data(unsigned char * pBuf,int nBufLength,ngx_flv_avc_config_header_t node)
{
	if(ngx_flv_right_bigger(nBufLength,sizeof(node.configurationVersion)))
		return 0;
	int nLenght = 0;
	nLenght += ngx_flv_mem_cp(pBuf,&node.configurationVersion,sizeof(node.configurationVersion));

	if(ngx_flv_right_bigger(nBufLength,nLenght + sizeof(node.AVCProfileIndication)))
		return 0;
	nLenght += ngx_flv_mem_cp(pBuf+nLenght,&node.AVCProfileIndication,sizeof(node.AVCProfileIndication));

	if(ngx_flv_right_bigger(nBufLength,nLenght + sizeof(node.profile_compatibility)))
		return 0;
	nLenght += ngx_flv_mem_cp(pBuf+nLenght,&node.profile_compatibility,sizeof(node.profile_compatibility));

	if(ngx_flv_right_bigger(nBufLength,nLenght + sizeof(node.AVCLevelIndication)))
		return 0;

	nLenght += ngx_flv_mem_cp(pBuf+nLenght,&node.AVCLevelIndication,sizeof(node.AVCLevelIndication));

	if(ngx_flv_right_bigger(nBufLength,nLenght + sizeof(node.lenghtSizeMinusOne)))
		return 0;
	nLenght += ngx_flv_mem_cp(pBuf+nLenght,&node.lenghtSizeMinusOne,sizeof(node.lenghtSizeMinusOne));

	if(ngx_flv_right_bigger(nBufLength,nLenght + sizeof(node.numOfSequenceParameterSets)))
		return 0;
	nLenght += ngx_flv_mem_cp(pBuf+nLenght,&node.numOfSequenceParameterSets,sizeof(node.numOfSequenceParameterSets));
    if(node.sps)
    {
	    if(ngx_flv_right_bigger(nBufLength,nLenght + node.nspsLenght+sizeof(short_2)))
		    return 0;
        short_2 sps_len = node.nspsLenght;
        sps_len = big_endian_16(sps_len);
        nLenght += ngx_flv_mem_cp(pBuf+nLenght,&sps_len,sizeof(short_2));
	    nLenght += ngx_flv_mem_cp(pBuf+nLenght,node.sps,node.nspsLenght);
    }
	if(ngx_flv_right_bigger(nBufLength,nLenght + sizeof(node.numOfPictureParameterSets)))
		return 0;
	nLenght += ngx_flv_mem_cp(pBuf+nLenght,&node.numOfPictureParameterSets,sizeof(node.numOfPictureParameterSets));

	if(node.nppsLenghth >= 0)
	{
		if(ngx_flv_right_bigger(nBufLength,nLenght + node.nppsLenghth + +sizeof(short_2)))
			return 0;
        short_2 pps_len = node.nppsLenghth;
        pps_len = big_endian_16(pps_len);
        nLenght += ngx_flv_mem_cp(pBuf+nLenght,&pps_len,sizeof(short_2));
		nLenght += ngx_flv_mem_cp(pBuf+nLenght,node.pps,node.nppsLenghth);
	}
	return nLenght;
}

ngx_chain_t* ngx_http_flv_perpare_video_header(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h
        ,ngx_chain_t *out)
{
    u_char *avc = NULL;
    u_char *sps = NULL;
    u_char *pps = NULL;

    unsigned int avc_buf_len = 1024;
    unsigned int nspsLength = 0;
    unsigned int nppsLength = 0;
    int_4 stamp = 0;

    //tag header
    unsigned int nIndex = 0;
    avc[nIndex++] = 0x09; //类型

	int n_tag_size_pos = nIndex; //tag size pos
	nIndex += 3;

	unsigned char * buf = avc+nIndex;
	FLVFILECOPYSTMP(stamp,buf); //时间戳
	nIndex += sizeof(int_4);
	avc[nIndex++] = 0;
	avc[nIndex++] = 0;
	avc[nIndex++] = 0;

    //amf header
    ngx_flv_video_avc_header_t  avc_amf_header;
	avc_amf_header.Type = 0x17;
	avc_amf_header.AVCPacketType = 0x0;
	avc_amf_header.compositiontime[0] = 0x0;
	avc_amf_header.compositiontime[1] = 0x0;
	avc_amf_header.compositiontime[2] = 0x0;
	if(ngx_flv_right_bigger(avc_buf_len,sizeof(ngx_flv_video_avc_header_t)))
		return NULL;

	unsigned int amf_size = ngx_flv_mem_cp(avc+nIndex,&avc_amf_header,sizeof(ngx_flv_video_avc_header_t));
    nIndex += amf_size;
    //media data
	ngx_flv_avc_config_header_t avc_tag_header;
	avc_tag_header.configurationVersion = 0x1;
	avc_tag_header.AVCProfileIndication = sps[1];
	avc_tag_header.profile_compatibility = sps[2];
	avc_tag_header.AVCLevelIndication = sps[3];
	avc_tag_header.lenghtSizeMinusOne = 0xff;

	avc_tag_header.numOfSequenceParameterSets = 0xE1;
    avc_tag_header.sps = (char*)sps;
	avc_tag_header.nspsLenght = nspsLength;

	if(nppsLength <= 0)
	{
		avc_tag_header.numOfPictureParameterSets = 0;
		avc_tag_header.nppsLenghth = 0;
		avc_tag_header.pps = NULL;
	}
	else
	{
		avc_tag_header.numOfPictureParameterSets = 0x1;
        avc_tag_header.pps = (char*)pps;
		avc_tag_header.nppsLenghth = nppsLength;
	}

	unsigned int payload_size = ngx_prepare_flv_avc_header_data(avc+nIndex,avc_buf_len-nIndex,avc_tag_header);

    nIndex += payload_size; 
    payload_size += amf_size;
    //tag size
    int_4 tag_size = nIndex;
	tag_size = big_endian_32(tag_size);

	int nBufLen = avc_buf_len - nIndex;

	if(ngx_flv_right_bigger(nBufLen,sizeof(tag_size)))
		return NULL;

	nIndex += ngx_flv_mem_cp(avc+nIndex,&tag_size,sizeof(tag_size));
    //data size
	put_int_to_three_char(avc+n_tag_size_pos,payload_size);
    return out;
}

int  ngx_audio_specific_config (unsigned char objectType,int samplerate, int channels, unsigned char *p)
{
	int rates [] = { 96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350, 0 };
	unsigned char count = 0;
	for (count = 0; rates[count] != samplerate; count++)
	{
		if (rates [count] == 0)
			return 0;
	}
	p[0] = ((objectType << 3) | (count >> 1));
	p[1] = (((count) & 0x01) << 7) | (channels << 3);
	return 2;
}

ngx_chain_t* 
ngx_http_flv_perpare_audio_header(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *out)
{
    u_char* aac = NULL;
    unsigned int aac_len = 1024;
    unsigned int payload_size = 0;
    int_4 stamp = 0;
    int_4 samplerate = 0;
    int_4 channels = 0;
    char object_type = 0;
    //tag header
    unsigned int nIndex = 0;
    aac[nIndex++] = 0x09; //类型

	int n_tag_size_pos = nIndex; //tag size pos
	nIndex += 3;
    unsigned char * buf = aac+nIndex;
	FLVFILECOPYSTMP(stamp,buf); //时间戳
	nIndex += sizeof(int_4);
	aac[nIndex++] = 0;
	aac[nIndex++] = 0;
	aac[nIndex++] = 0;

    //tag data
    u_char* p = aac + nIndex;
     if(samplerate == 5500)
    {
        p[0] = 0x00;
    }
    if(samplerate <= 11025)
    {
        p[0] = 0x04;
    }
    else if(samplerate <= 22050)
    {
        p[0] = 0x08;
    }
    else 
    {
        p[0] = 0x0c;
    }

    int c = ngx_audio_specific_config(object_type,samplerate,channels,p+2);
    p[0] |= 0xA3; // AAC audio, need these codes first
    p[1] = 0x0;

    payload_size = (2+c);

    nIndex += payload_size;

    //tag size
    int_4 tag_size = nIndex;
	tag_size = big_endian_32(tag_size);
	int nBufLen = aac_len - nIndex;

	if(ngx_flv_right_bigger(nBufLen,sizeof(tag_size)))
		return NULL;

	nIndex += ngx_flv_mem_cp(aac+nIndex,&tag_size,sizeof(tag_size));
    //data size
	put_int_to_three_char(aac+n_tag_size_pos,payload_size);

    return out;
}

ngx_chain_t* ngx_http_flv_perpare_meta_header(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h
                                        ,ngx_chain_t *out) //header =  flv header tag + mediadata tag
{
    ngx_rtmp_codec_ctx_t  *codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if(codec_ctx == NULL)
        return NULL;

    u_char flv_header[13] = {0};
    ngx_int_t flv_len  = 0;

    unsigned int buf_len = 1024;
    int need_duration_and_filesize = 0;
    unsigned int duration_pos = 0;
    unsigned int file_size_pos = 0;
    ngx_flv_media_data_t meta;
    unsigned int meta_data_size = 0;
    unsigned int flv_header_size = 0;
    u_char buf[1024] = {0};
    // flv tag
    int has_video = codec_ctx->aac_header == NULL ? 0 : 1;
    int has_audio = codec_ctx->avc_header == NULL ? 0 : 1;
    memset(&meta,0,sizeof(ngx_flv_media_data_t));

    if(ngx_perpare_flv_header(flv_header,has_video,has_audio,&flv_header_size) == NGX_ERROR)
        return NULL;
    
    flv_len += flv_header_size;
    
    //media data tag
    if(ngx_prepare_flv_media_data(buf,buf_len,need_duration_and_filesize,has_video,has_audio,&duration_pos,&file_size_pos,meta,&meta_data_size) == NGX_ERROR)
        return NULL;

    flv_len += meta_data_size;
    return out;
}

ngx_int_t ngx_http_flv_prepare_message(ngx_rtmp_header_t *h,ngx_chain_t* in, ngx_chain_t *out,unsigned int * out_size)
{
    if(h == NULL || in == NULL  || out == NULL)
        return NGX_ERROR;
    
    if(in->buf == NULL ||  out->buf == NULL)
        return NGX_ERROR;

    u_char* data = out->buf->pos;
    unsigned int payload_size = 0;
    int_4 stamp = h->timestamp;

    unsigned int data_buf_len = out->buf->end - out->buf->pos;
    if(data_buf_len <= 16)
        return NGX_ERROR;

    //tag header
    unsigned int nIndex = 0;
    if (h->type == NGX_RTMP_MSG_AUDIO) {
        data[nIndex++] = 0x08; //类型
    } else if (h->type == NGX_RTMP_MSG_VIDEO) {
        data[nIndex++] = 0x09; //类型
    } else {
        return NGX_ERROR;
    }
    
    // data size pos
	int n_tag_size_pos = nIndex; 
	nIndex += 3;

    // timestamp  
	unsigned char *buf = data+nIndex;
	FLVFILECOPYSTMP(stamp, buf); 
	nIndex += sizeof(int_4);
	// stream id 
    data[nIndex++] = 0;
	data[nIndex++] = 0;
	data[nIndex++] = 0;
    
    // tag_data
    buf = data+nIndex;
    while(in) {
        int copy_size = in->buf->last - in->buf->pos;
        memcpy(buf + payload_size,in->buf->pos,copy_size);
        in = in->next;
        payload_size += copy_size;
    }
    nIndex += payload_size; 
    
    // pre tag size
    int_4 tag_size = nIndex;
	tag_size = big_endian_32(tag_size);
	int nBufLen = data_buf_len - nIndex;
    
	if (ngx_flv_right_bigger(nBufLen, sizeof(tag_size)))
		return NGX_ERROR;
    
	nIndex += ngx_flv_mem_cp(data+nIndex, &tag_size, sizeof(tag_size));
    
    // data size
	put_int_to_three_char(data+n_tag_size_pos, payload_size);
    *out_size = nIndex;
    out->buf->last = out->buf->pos + nIndex;
    return NGX_OK;
}

// header =  flv header tag + mediadata tag + aac_tag + avc_tag(sps pps)
ngx_int_t 
ngx_http_flv_perpare_header(ngx_rtmp_session_t *session, void *ctx, ngx_rtmp_header_t *h) 
{
   if (ctx == NULL || h == NULL)
        return NGX_ERROR;

    ngx_rtmp_codec_ctx_t  *codec_ctx = ngx_rtmp_get_module_ctx(session, ngx_rtmp_codec_module);
    if (codec_ctx == NULL)
        return NGX_ERROR;

    ngx_http_rtmp_live_ctx_t *hctx = (ngx_http_rtmp_live_ctx_t*)ctx;
    ngx_http_rtmp_live_stream_t *stream = hctx->stream;
    if (stream == NULL)
        return NGX_ERROR;
    
    // 缓存 meta data 
    if ( stream->meta_conf_tag == NULL){
        stream->meta_conf_tag = ngx_http_flv_base_alloc_tag_mem(stream->tag_buf_len);
    }

    if (stream->meta_conf_tag){
        stream->meta_conf_tag->buf->pos = stream->meta_conf_tag->buf->last;
        stream->meta_tag_size = 0;
    } else {
        return NGX_ERROR;
    }

    u_char *flv = stream->meta_conf_tag->buf->pos;
    ngx_int_t flv_len  = 0;
    unsigned int flv_header_size = 0;    
    unsigned int buf_len = 0;
    int need_duration_and_filesize = 0;
    unsigned int duration_pos = 0;
    unsigned int file_size_pos = 0;

    ngx_flv_media_data_t meta;
    memset(&meta, 0, sizeof(ngx_flv_media_data_t));
    meta.video_fps          = stream->frame_rate;   // 视频帧率
	meta.video_width        = stream->width;        // 视频宽
	meta.video_height       = stream->height;       // 视频高
	meta.audio_samplerate   = stream->sample_rate;
    meta.audio_samplesize   = stream->sample_size;
    meta.video_data_rate    = stream->video_data_rate;
    meta.audio_data_rate    = 0;
    
    unsigned int meta_data_size = 0;
    u_char *buf = NULL;
    
    // flv header
    int has_video = codec_ctx->aac_header == NULL ? 0 : 1;
    int has_audio = codec_ctx->avc_header == NULL ? 0 : 1;
    if (ngx_perpare_flv_header(flv, has_video, has_audio, &flv_header_size) == NGX_ERROR)
        return NGX_ERROR;
    flv_len += flv_header_size;

    buf  = flv + flv_len;
    buf_len = stream->tag_buf_len - flv_len;
    // media data tag
    if (ngx_prepare_flv_media_data(buf, buf_len, need_duration_and_filesize, has_video, has_audio, &duration_pos, &file_size_pos, meta, &meta_data_size) == NGX_ERROR)
        return NGX_ERROR;

    flv_len += meta_data_size;
    uint8_t                 hhh_type = h->type; 
    stream->meta_tag_size = flv_len;
    stream->meta_conf_tag->buf->last = stream->meta_conf_tag->buf->pos + flv_len;
    
    // 缓存 AAC 
    // audio header tag
    if (has_audio) {
        if (stream->aac_conf_tag == NULL) 
            stream->aac_conf_tag = ngx_http_flv_base_alloc_tag_mem(stream->tag_buf_len);
        
        if (stream->aac_conf_tag) {
            stream->aac_conf_tag->buf->pos = stream->aac_conf_tag->buf->last;
            stream->aac_tag_size = 0;
        } else {
            return NGX_ERROR;
        }
        
        h->type = NGX_RTMP_MSG_AUDIO;
        if (ngx_http_flv_prepare_message(h, codec_ctx->aac_header, stream->aac_conf_tag, &stream->aac_tag_size) == NGX_ERROR)
            return NGX_ERROR;
    }
    
    // 缓存 AVC
    // video header tag
    if (has_video) {
        if ( stream->avc_conf_tag == NULL)
            stream->avc_conf_tag = ngx_http_flv_base_alloc_tag_mem(stream->tag_buf_len);
        
        if (stream->aac_conf_tag) {
            stream->avc_conf_tag->buf->pos = stream->avc_conf_tag->buf->last;
            stream->avc_tag_size = 0;
        } else {
            return NGX_ERROR;
        }
        
        h->type = NGX_RTMP_MSG_VIDEO;
        if (ngx_http_flv_prepare_message(h, codec_ctx->avc_header, stream->avc_conf_tag, &stream->avc_tag_size) == NGX_ERROR)
            return NGX_ERROR;
    }

    h->type = hhh_type;
    return NGX_OK;
}
