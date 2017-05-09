#include "ngx_flv_handler.h"


//tagÊ±¼ä´ÁµÚËÄÎ»ÊÇÀ©Õ¹Î»
//ffmpegÖÐÊÇ7f TagStamp[3] = v & 0x7f

int flv_big_endian_test()  
{  
	const short n = 1;  
	if(*(char *)&n)  
	{  
		return FLV_LITTLEENDIAN;  
	}  
	return FLV_BIGENDIAN;  
} 

void flv_put_num_to_buf(unsigned char szNum[],const char * psrc,int dstLenght)
{
    int n = 0;
	if(flv_big_endian_test())
	{
		for (; n < dstLenght; ++n)
		{
			szNum[n] = psrc[n];
		}
	}
	else
	{
        n = 0;
		for (; n < dstLenght; ++n)
		{
			szNum[n] = psrc[dstLenght -1 - n];
		}
	}
}

int ngx_flv_right_bigger(int left,int right)
{
	if(left < right)
	{
		printf("flv:dst size is smaller\n");
		return 1;
	}
	return 0;
}

int ngx_flv_mem_cp(void *dst,const void * src,int size)
{
	memcpy(dst,src,size);
	return size;
}

int ngx_flv_write_amf_header(unsigned char * dst,int ndstlen,const ngx_flv_amf_header_t  amf_header)
{
	int nm_databufsize = 0;

	if(ngx_flv_right_bigger(ndstlen,sizeof(amf_header.amf1_type)))
		return 0;

	nm_databufsize += ngx_flv_mem_cp(dst,&amf_header.amf1_type,sizeof(amf_header.amf1_type));
	
	if(ngx_flv_right_bigger(ndstlen,sizeof(amf_header.str_len)+nm_databufsize))
		return 0;

	short_2 stringLength = big_endian_16(amf_header.str_len);
	nm_databufsize += ngx_flv_mem_cp(dst+nm_databufsize,&stringLength,sizeof(amf_header.str_len));

	if(ngx_flv_right_bigger(ndstlen,amf_header.str_len+nm_databufsize))
		return 0;

	nm_databufsize += ngx_flv_mem_cp(dst+nm_databufsize,amf_header.ptr,amf_header.str_len);

	if(ngx_flv_right_bigger(ndstlen,sizeof(amf_header.amf2_type)+nm_databufsize))
		return 0;

	nm_databufsize += ngx_flv_mem_cp(dst+nm_databufsize,&amf_header.amf2_type,sizeof(amf_header.amf2_type));

	if(ngx_flv_right_bigger(ndstlen,sizeof(amf_header.arr_size)+nm_databufsize))
		return 0;
	int_4 arraySize = big_endian_32(amf_header.arr_size);
	nm_databufsize += ngx_flv_mem_cp(dst+nm_databufsize,&arraySize,sizeof(amf_header.arr_size));

	return nm_databufsize;
}

int ngx_flv_creatm_databufNodeCommon(const char * szName,char nameLength[2],char* name )
{
	int nSize = 0;
	short_2 nNameLenght = strlen(szName);
	nSize += nNameLenght;
	strcpy(name,szName);

	nNameLenght = big_endian_16(nNameLenght);
	memcpy(nameLength,&nNameLenght,sizeof(short_2));
	nSize += sizeof(short_2);
	return nSize;
}

int ngx_flv_createm_databufNode(const char * szName,double data, ngx_flv_amf_array_node_t *node)
{
	if(node == NULL ||  szName == NULL)
		return 0;

	int nSize = ngx_flv_creatm_databufNodeCommon(szName,node->name_len,node->name);

	node->type = 0x0;//doubleÀàÐÍ
	nSize += sizeof(node->type);

	node->data = data;
	nSize += sizeof(node->data);
	return nSize;
}

// int ngx_flv_createm_bdatabufNode(const char * szName,bool data, ngx_flv_amf_bool_array_node_t *node)
int ngx_flv_createm_bdatabufNode(const char * szName,int data, ngx_flv_amf_bool_array_node_t *node)
{
	if(node == NULL ||  szName == NULL)
		return 0;
	int nSize = ngx_flv_creatm_databufNodeCommon(szName,node->name_len,node->name);

	node->type = 0x1;//bool 
	nSize += sizeof(node->type);

	node->data = data ? 1 : 0;
	nSize += sizeof(node->data);
	return nSize;
}

int ngx_flv_wrtitem_databufNode(unsigned char * buf,int nLength,const  ngx_flv_amf_array_node_t node)
{

	if(ngx_flv_right_bigger(nLength,sizeof(node.name_len)))
		return 0;
	int n_ret_sie = 0;
	n_ret_sie = ngx_flv_mem_cp(buf,node.name_len,sizeof(node.name_len));
		
	if(ngx_flv_right_bigger(nLength,n_ret_sie + strlen(node.name)))
		return 0;
	n_ret_sie += ngx_flv_mem_cp(buf+n_ret_sie,node.name,strlen(node.name));

	if(ngx_flv_right_bigger(nLength,n_ret_sie + sizeof(node.type)))
		return 0;
	n_ret_sie += ngx_flv_mem_cp(buf+n_ret_sie,&node.type,sizeof(node.type));

	if(ngx_flv_right_bigger(nLength,n_ret_sie + sizeof(double)))
		return 0;
	put_double_to_eight_char(buf+n_ret_sie,node.data);

	return n_ret_sie + sizeof(double);
}

int ngx_flv_wrtitem_bdatabufNode(unsigned char * buf,int nLength,const  ngx_flv_amf_bool_array_node_t node)
{
	if(ngx_flv_right_bigger(nLength,sizeof(node.name_len)))
		return 0;
	int n_ret_sie = 0;
	n_ret_sie = ngx_flv_mem_cp(buf,node.name_len,sizeof(node.name_len));

	if(ngx_flv_right_bigger(nLength,n_ret_sie + strlen(node.name)))
		return 0;

	n_ret_sie += ngx_flv_mem_cp(buf+n_ret_sie,node.name,strlen(node.name));

	if(ngx_flv_right_bigger(nLength,n_ret_sie + sizeof(node.type)))
		return 0;
	n_ret_sie += ngx_flv_mem_cp(buf+n_ret_sie,&node.type,sizeof(node.type));

	if(ngx_flv_right_bigger(nLength,n_ret_sie + sizeof(node.data)))
		return 0;
    n_ret_sie += ngx_flv_mem_cp(buf+n_ret_sie,&node.data,sizeof(node.data));
	return n_ret_sie;
}
