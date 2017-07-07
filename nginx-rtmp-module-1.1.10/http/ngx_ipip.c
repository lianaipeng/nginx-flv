#include "ngx_ipip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char byte;
typedef unsigned int uint;
#define B2IL(b) (((b)[0] & 0xFF) | (((b)[1] << 8) & 0xFF00) | (((b)[2] << 16) & 0xFF0000) | (((b)[3] << 24) & 0xFF000000))
#define B2IU(b) (((b)[3] & 0xFF) | (((b)[2] << 8) & 0xFF00) | (((b)[1] << 16) & 0xFF0000) | (((b)[0] << 24) & 0xFF000000))

struct {
    byte *data;
    byte *index;
    uint *flag;
    uint offset;
} ipip;

int destroy() {
    if (!ipip.offset) {
        return 0;
    }
    free(ipip.flag);
    free(ipip.index);
    free(ipip.data);
    ipip.offset = 0;
    return 0;
}

int init(const char* ipdb) {
    if (ipip.offset) {
        return 0;
    }
    FILE *file = fopen(ipdb, "rb");
    if(file == NULL)
        return 0;

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    ipip.data = (byte *) malloc(size * sizeof(byte));
    fread(ipip.data, sizeof(byte), (size_t) size, file);
    
    fclose(file);
    
    uint indexLength = B2IU(ipip.data);
    
    ipip.index = (byte *) malloc(indexLength * sizeof(byte));
    memcpy(ipip.index, ipip.data + 4, indexLength);
    
    ipip.offset = indexLength;
    
    ipip.flag = (uint *) malloc(65536 * sizeof(uint));
    memcpy(ipip.flag, ipip.index, 65536 * sizeof(uint));
    
    return 0;
}

int find(const char *ip, char *result) {
    uint ips[4];
    int num = sscanf(ip, "%d.%d.%d.%d", &ips[0], &ips[1], &ips[2], &ips[3]);
    if (num == 4) {
        uint ip_prefix_value = ips[0] * 256 + ips[1];
        uint ip2long_value = B2IU(ips);
        uint start = ipip.flag[ip_prefix_value];
        uint max_comp_len = ipip.offset - 262144 - 4;
        uint index_offset = 0;
        uint index_length = 0;
        for (start = start * 9 + 262144; start < max_comp_len; start += 9) {
            if (B2IU(ipip.index + start) >= ip2long_value) {
                index_offset = B2IL(ipip.index + start + 4) & 0x00FFFFFF;
                index_length = (ipip.index[start+7] << 8) + ipip.index[start+8];
                break;
            }
        }
        memcpy(result, ipip.data + ipip.offset + index_offset - 262144, index_length);
        result[index_length] = '\0';
    }
    return 0;
}

char *strtok_r_2(char *str, char const *delims, char **context)
{
	char *p, *ret = NULL;
	if (str != NULL)
		*context = str;
	if (*context == NULL)
		return NULL;
	if ((p = strpbrk(*context, delims)) != NULL) 
	{
		*p = 0;
		ret = *context;
		*context = ++p;
	}
	else if (**context)
	{
		ret = *context;
		*context = NULL;
	}
	return ret;
}

int get_isp_info(char* ip,char* result,int len)
{
    char res[1024] = {'\0'};
    char tmp[1024] = {'\0'};
    find(ip, res);
    char *lasts;
    int i = 0;
    char* rst = strtok_r_2(res, "\t", &lasts);
    while (rst && i++ <= 4)
    {
        if(i != 1 && i != 3)
        {
            if(i == 2)
            {
                strcpy(tmp,rst);
            }
            else
            {
                if(rst[0] != '\0')
                    sprintf(tmp,"%s_%s",tmp,rst);
            }
        }
        rst = strtok_r_2(NULL, "\t", &lasts);
    }
    int slen = strlen(tmp);
    int size = (len - 1) >= slen ? slen : len -1;
    strncpy(result,tmp,size);
    result[size] = '\0';
    return 1;
}

int check_ip_allow(char* ip,char* isp_name,char* file_name,char* client_isp_name)
{
    if (!ipip.offset) {
        init(file_name);
    }
    if(strlen(client_isp_name) < 2){
        get_isp_info(ip,client_isp_name,1024);
    }

    if(strcmp(isp_name,client_isp_name) == 0){
        return 1;
    }
    return 0;
}