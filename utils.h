#ifndef __HPATCH_UTILS__
#define __HPATCH_UTILS__

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

void hdebug(const char *msg);

/* a type safe version of bsearch() */
#define xbsearch(key, base, nmemb, compar)				\
({									\
	typeof(&(base)[0]) __ret = NULL;				\
	if (nmemb > 0) {						\
		assert(compar(key, key) == 0);				\
		assert(compar(base, base) == 0);			\
		__ret = bsearch(key, base, nmemb, sizeof(*(base)),	\
				(comparison_fn_t)compar);		\
	}								\
	__ret;								\
})

/*
 * Compares two integer values
 *
 * If the first argument is larger than the second one, intcmp() returns 1.  If
 * two members are equal, returns 0.  Otherwise, returns -1.
 */
#define intcmp(x, y) \
({					\
	typeof(x) _x = (x);		\
	typeof(y) _y = (y);		\
	(void) (&_x == &_y);		\
	_x < _y ? -1 : _x > _y ? 1 : 0;	\
})

/* a type safe version of qsort() */
#define xqsort(base, nmemb, compar)					\
({									\
	if (nmemb > 1) {						\
		qsort(base, nmemb, sizeof(*(base)),			\
		      (comparison_fn_t)compar);				\
		assert(compar(base, base + 1) <= 0);			\
	}								\
})

#endif
