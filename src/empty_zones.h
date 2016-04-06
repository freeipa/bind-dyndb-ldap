#include <isc/event.h>

#include "util.h"

extern const char *empty_zones[];

typedef struct empty_zone_search {
	DECLARE_BUFFERED_NAME(qname);
	DECLARE_BUFFERED_NAME(ezname);
	unsigned int nextidx;
	dns_namereln_t namerel;
} empty_zone_search_t;

isc_result_t
empty_zone_search_next(empty_zone_search_t *iter) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
empty_zone_search_init(empty_zone_search_t *iter, dns_name_t *qname) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
empty_zone_handle_conflicts(dns_name_t *name, dns_zt_t *zonetable,
			    isc_boolean_t warn_only) ATTR_NONNULLS ATTR_CHECKRESULT;

/* Trigger to execute empty_zone_handle_conflicts() for dns_rootname. */
#define LDAPDB_EVENT_GLOBALFWD_HANDLEEZ	(LDAPDB_EVENTCLASS + 5)

typedef struct ldap_globalfwd_handleez ldap_globalfwd_handleez_t;
struct ldap_globalfwd_handleez {
	ISC_EVENT_COMMON(ldap_globalfwd_handleez_t);
	isc_boolean_t warn_only;
};

void
empty_zone_handle_globalfwd_ev(isc_task_t *task, isc_event_t *event) ATTR_NONNULLS;
