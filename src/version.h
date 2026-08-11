#pragma once

namespace nano {

/// Project version, injected by CMake from the project() declaration so there is
/// exactly one place it is written down.
const char* version() noexcept;

}  // namespace nano
