# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# "Trim" the build. Include the minimal set of components, main, and anything it depends on.
idf_build_set_property(MINIMAL_BUILD ON)
# Explicit version, <MM>.<NN> fixed 5-char format per doc/M2M_SW Release
# Naming Guide v2.0 section 4.4 (01.00 is the first release under this
# scheme -- see that section's own guidance to restart numbering rather
# than continue the ad-hoc 1.0.x sequence used before this doc existed).
# Single source of truth for the version: components/at_modem/m2m_version.h's
# M2M_FW_VERSION is generated from this same value (see that component's
# CMakeLists.txt), so AT*M2M*SYS_VER/OTA_CHECK/the release filename can never
# disagree. Bump by hand per the naming guide's MM/NN increment rules (4.4)
# until there's an automated release process.
set(PROJECT_VER "01.00")
project(esp32_c3)
