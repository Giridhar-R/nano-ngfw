#include "version.h"

#ifndef NANO_VERSION
#define NANO_VERSION "0.0.0-unconfigured"
#endif

namespace nano {

const char* version() noexcept { return NANO_VERSION; }

}  // namespace nano
