#ifndef _LD_UTIL_H_
#define _LD_UTIL_H_

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)

#endif /* !_LD_UTIL_H_ */
