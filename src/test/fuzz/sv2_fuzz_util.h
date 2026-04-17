// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_SV2_FUZZ_UTIL_H
#define BITCOIN_TEST_FUZZ_SV2_FUZZ_UTIL_H

#include <logging.h>
#include <test/sv2_test_setup.h>

#include <cstdlib>
#include <functional>
#include <string_view>
#include <vector>

// Exposed by the fuzz harness to pass through double-dash arguments.
extern const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS;

/**
 * Shared initialization for SV2 fuzz targets.
 *
 * Sets up the test context and optionally enables console logging
 * when requested via double-dash arguments or environment variables.
 *
 * Supported flags: --printtoconsole, --debug=sv2, --loglevel=sv2:trace
 * Environment: SV2_FUZZ_LOG=1 or SV2_FUZZ_LOG_DEBUG=1
 */
inline void Sv2FuzzInitialize()
{
    static const auto testing_setup = std::make_unique<const Sv2BasicTestingSetup>();

    bool want_console{false};
    bool want_sv2_debug{false};
    bool want_sv2_trace{false};
    if (G_TEST_COMMAND_LINE_ARGUMENTS) {
        for (const char* arg : G_TEST_COMMAND_LINE_ARGUMENTS()) {
            if (!arg) continue;
            std::string_view s{arg};
            if (s == "--printtoconsole" || s == "--printtoconsole=1") want_console = true;
            if (s == "--debug=sv2" || s == "--debug=1" || s == "--debug=all") want_sv2_debug = true;
            if (s == "--loglevel=sv2:trace" || s == "--loglevel=trace") want_sv2_trace = true;
        }
    }
    if (want_console || std::getenv("SV2_FUZZ_LOG")) {
        LogInstance().m_print_to_console = true;
        LogInstance().EnableCategory(BCLog::SV2);
        if (want_sv2_trace) {
            LogInstance().SetCategoryLogLevel({{BCLog::SV2, BCLog::Level::Trace}});
        } else if (want_sv2_debug || std::getenv("SV2_FUZZ_LOG_DEBUG")) {
            LogInstance().SetCategoryLogLevel({{BCLog::SV2, BCLog::Level::Debug}});
        }
        LogInstance().StartLogging();
    }
}

#endif // BITCOIN_TEST_FUZZ_SV2_FUZZ_UTIL_H
