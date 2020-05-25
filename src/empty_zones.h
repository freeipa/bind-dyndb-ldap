#include <isc/event.h>

#include <dns/types.h>

#include "util.h"

extern const char *empty_zones[];

typedef struct empty_zone_search {
	DECLARE_BUFFERED_NAME(qname);
	DECLARE_BUFFERED_NAME(ezname);
	unsigned int nextidx;
	dns_namereln_t namerel;
	dns_zt_t *zonetable;
} empty_zone_search_t;

isc_result_t
empty_zone_search_next(empty_zone_search_t *iter) ATTR_NONNULLS ATTR_CHECKRESULT;

void
empty_zone_search_stop(empty_zone_search_t *iter) ATTR_NONNULLS;

isc_result_t
empty_zone_search_init(empty_zone_search_t *iter, const dns_name_t *qname,
		       dns_zt_t *ztable) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
empty_zone_handle_conflicts(const dns_name_t *name, dns_zt_t *zonetable,
			    bool warn_only) ATTR_NONNULLS ATTR_CHECKRESULT;

/* Trigger to execute empty_zone_handle_conflicts() for dns_rootname. */
#define LDAPDB_EVENT_GLOBALFWD_HANDLEEZ	(LDAPDB_EVENTCLASS + 5)

typedef struct ldap_globalfwd_handleez ldap_globalfwd_handleez_t;
struct ldap_globalfwd_handleez {
	ISC_EVENT_COMMON(ldap_globalfwd_handleez_t);
	bool warn_only;
};

void
empty_zone_handle_globalfwd_ev(isc_task_t *task, isc_event_t *event) ATTR_NONNULLS;
