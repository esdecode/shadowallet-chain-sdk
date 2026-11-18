/* SHADOWALLET-PATCH: reaching the clock-based random fallback means the operating system produced no entropy. Abort. */
#include <stdlib.h>
long shadowallet_ltc_no_clock(void) {
    abort();
    return 0;
}
