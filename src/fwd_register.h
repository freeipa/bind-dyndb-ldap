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
fwdr_create(isc_mem_t *mctx, fwd_register_t **fwdrp) ATTR_NONNULLS ATTR_CHECKRESULT;

void
fwdr_destroy(fwd_register_t **fwdrp) ATTR_NONNULLS;

isc_result_t
fwdr_add_zone(fwd_register_t *fwdr, dns_name_t *zone) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
fwdr_del_zone(fwd_register_t *fwdr, dns_name_t *zone) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
fwdr_zone_ispresent(fwd_register_t *fwdr, dns_name_t *name) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
fwdr_rbt_iter_init(fwd_register_t *fwdr, rbt_iterator_t **iter,
		   dns_name_t *nodename) ATTR_NONNULLS ATTR_CHECKRESULT;

#endif /* !_LD_FWD_REGISTER_H_ */
