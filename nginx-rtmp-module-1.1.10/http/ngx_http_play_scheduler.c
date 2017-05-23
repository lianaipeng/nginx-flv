#include "ngx_http_play_scheduler.h"


ngx_int_t ngx_http_live_play_process_slot(u_char * name,ssize_t len)
{
    ngx_core_conf_t * ccf = (ngx_core_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);                                                                             

    if(ccf->worker_processes == 0) {
        return -1;
    }

    ngx_int_t slot = ngx_hash_key(name,len) % ccf->worker_processes;
    printf("worker_processes %ld ; slot %ld; ngx_process_slot %ld\n",ccf->worker_processes,slot,ngx_process_slot);

    if(slot == ngx_process_slot){
        return -1;
    }
    return slot;
}
