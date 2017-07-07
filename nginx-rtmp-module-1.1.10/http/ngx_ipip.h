#ifndef NGX_IPIP_H
#define NGX_IPIP_H

int init(const char* ipdb);
int destroy();
int find(const char *ip, char *result);

int get_isp_info(char* ip,char* result,int len);

int check_ip_allow(char* ip,char* isp_name,char* file_name,char* client_isp_name);
#endif //_NGX_IPIP_H_
