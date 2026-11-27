cmake_minimum_required(VERSION 3.13)
project(iwinfo LANGUAGES C VERSION 0)
add_compile_definitions(_GNU_SOURCE)
include(GNUInstallDirs)

option(IWINFO_BUILD_LUA "Build Lua 5.1 module" ON)
set(IWINFO_BACKENDS "nl80211;wext" CACHE STRING "Space/semicolon separated list of backends to enable (nl80211;wext;wl;madwifi)")

set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_options(-Wall -Wextra -Wformat -Werror=format-security -fno-omit-frame-pointer)

FIND_LIBRARY(ubox_library NAMES ubox)
FIND_LIBRARY(ubus_library NAMES ubus)
FIND_LIBRARY(uci_library NAMES uci)

FIND_PATH(ubox_include_dir libubox/usock.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})

FIND_PATH(ubus_include_dir libubus.h)
INCLUDE_DIRECTORIES(${ubus_include_dir})

FIND_PATH(uci_include_dir uci.h)
INCLUDE_DIRECTORIES(${uci_include_dir})

find_package(PkgConfig REQUIRED)
set(NL_LIBS "")
set(NL_CFLAGS "")
if (PKG_CONFIG_FOUND)
  pkg_check_modules(NLTINY QUIET libnl-tiny)
  if (NLTINY_FOUND)
    set(NL_LIBS   "${NLTINY_LINK_LIBRARIES}")
    set(NL_CFLAGS "${NLTINY_CFLAGS}")
    add_definitions(-DUSE_NL_TINY)
  else()
    pkg_check_modules(NL3 REQUIRED libnl-3.0 libnl-genl-3.0)
    set(NL_LIBS   "${NL3_LINK_LIBRARIES}")
    set(NL_CFLAGS "${NL3_CFLAGS}")
    add_definitions(-DUSE_LIBNL3)
  endif()
endif()

# Lua 5.1 (for module)
if (IWINFO_BUILD_LUA)
  pkg_check_modules(LUA51 REQUIRED lua5.1)
endif()

include_directories(
  ${CMAKE_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${ubox_include_dir}
  ${ubus_include_dir}
  ${uci_include_dir}
)
if (NL_CFLAGS)
  separate_arguments(_NL_CFLAGS NATIVE_COMMAND "${NL_CFLAGS}")
  add_compile_options(${_NL_CFLAGS})
endif()
if (IWINFO_BUILD_LUA)
  include_directories(${LUA51_INCLUDE_DIRS})
endif()

set(IWINFO_SRC
  iwinfo_utils.c
  iwinfo_lib.c
)

function(add_backend name def)
  list(FIND IWINFO_BACKENDS "${name}" _idx)
  if (_idx EQUAL -1)
    return()
  endif()

  add_definitions(-D${def})
  set(IWINFO_SRC ${IWINFO_SRC} ${ARGN} PARENT_SCOPE)
endfunction()

add_backend("nl80211" "USE_NL80211" iwinfo_nl80211.c)
add_backend("wext"    "USE_WEXT"    iwinfo_wext.c iwinfo_wext_scan.c)
add_backend("wl"      "USE_WL"      iwinfo_wl.c)
add_backend("madwifi" "USE_MADWIFI" iwinfo_madwifi.c)

if (IWINFO_BUILD_LUA AND EXISTS "${CMAKE_SOURCE_DIR}/iwinfo_lua.c")
  set(IWINFO_LUA_SRC iwinfo_lua.c)
endif()

add_library(iwinfo SHARED ${IWINFO_SRC})
target_link_libraries(iwinfo
  ${ubox_library}
  ${ubus_library}
  ${uci_library}
  ${NL_LIBS}
)

set_target_properties(iwinfo PROPERTIES
  SOVERSION 0
  VERSION 0.0.0
  OUTPUT_NAME "iwinfo"
)

add_executable(iwinfo_cli iwinfo_cli.c)

if (TARGET iwinfo_cli)
  target_link_libraries(iwinfo_cli iwinfo ${NL_LIBS} ${ubox_library} ${ubus_library} ${uci_library})
  set_target_properties(iwinfo_cli PROPERTIES OUTPUT_NAME "iwinfo")
  install(TARGETS iwinfo_cli RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
endif()

if (IWINFO_BUILD_LUA AND IWINFO_LUA_SRC)
  add_library(iwinfo_lua MODULE ${IWINFO_LUA_SRC})
  target_link_libraries(iwinfo_lua iwinfo ${LUA51_LINK_LIBRARIES})
  set_target_properties(iwinfo_lua PROPERTIES
    PREFIX ""
    OUTPUT_NAME "iwinfo"
  )
  install(TARGETS iwinfo_lua LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/lua/5.1)
endif()

install(TARGETS iwinfo LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES include/iwinfo.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/iwinfo/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iwinfo FILES_MATCHING PATTERN "*.h")

message(STATUS "Backends enabled: ${IWINFO_BACKENDS}")
if (NLTINY_FOUND)
  message(STATUS "Using libnl-tiny")
else()
  message(STATUS "Using libnl-3/libnl-genl-3")
endif()
if (IWINFO_BUILD_LUA AND IWINFO_LUA_SRC)
  message(STATUS "Building Lua 5.1 module")
else()
  message(STATUS "Lua module disabled or source not found")
endif()

ADD_CUSTOM_TARGET(debian
        COMMAND ${CMAKE_COMMAND} -E echo "Generating debian/changelog from git..."
        COMMAND ${CMAKE_SOURCE_DIR}/debian/generate-changelog.sh
        COMMAND dpkg-buildpackage -b -uc -us
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Building Debian package"
)
