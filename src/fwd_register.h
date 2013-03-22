#ifndef _LD_FWD_REGISTER_H_
#define _LD_FWD_REGISTER_H_

#include <dns/rbt.h>
#include <dns/result.h>

#define FORWARDING_SET_MARK ((void *)1)
/*
#if FORWARDING_SET_MARK == NULL
	#error "FAIL!"
#endif
*/

typedef struct fwd_register fwd_register_t;

isc_result_t
fwdr_create(isc_mem_t *mctx, fwd_register_t **fwdrp);

void
fwdr_destroy(fwd_register_t **fwdrp);

isc_result_t
fwdr_add_zone(fwd_register_t *fwdr, dns_name_t *zone);

isc_result_t
fwdr_del_zone(fwd_register_t *fwdr, dns_name_t *zone);

isc_result_t
fwdr_zone_ispresent(fwd_register_t *fwdr, dns_name_t *name);

isc_result_t
fwdr_rbt_iter_init(fwd_register_t *fwdr, rbt_iterator_t *iter,
		   dns_name_t *nodename);

#endif /* !_LD_FWD_REGISTER_H_ */
