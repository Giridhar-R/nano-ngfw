#pragma once

#include <string>

#include "engine.h"

namespace nano {

// ---------------------------------------------------------------------------
// Self-contained HTML session report.
//
// A firewall with no management view is the odd one out -- PAN-OS is
// administered almost entirely through a web GUI, and the session browser is the
// screen an operator actually lives in. This is the same idea at 1/1000 scale.
//
// Written by the binary rather than by a separate web application, for the same
// reason nothing else here has a dependency: a single file with inline CSS opens
// in any browser, survives being emailed, and cannot rot when a JavaScript
// toolchain moves on. There is no server, no build step, and no fetch -- the
// report is a rendering of one run, fixed at the moment it was written.
// ---------------------------------------------------------------------------

/// Writes a report for the run held in `engine` to `path`.
/// `capture` and `policy` are shown in the header for provenance.
/// Returns false if the file could not be opened.
bool write_html_report(const std::string& path, const Engine& engine,
                       const std::string& capture, const std::string& policy);

}  // namespace nano
