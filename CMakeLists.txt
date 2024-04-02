project(pkg_pfs_tool)
cmake_minimum_required(VERSION 3.12)

#
# Compiler settings.
#

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

#
# Third-party dependendices.
#

string(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

if(MINGW)
	# hack to force static zlib (but it doesn't mess anything else up...)
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
	#list(APPEND LIBS ucrt)
endif()

if(USE_SYSTEM_ZLIB)
  set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
  find_package(ZLIB)
  if(NOT ${ZLIB_FOUND})
    message(WARNING "zlib target not found! USE_SYSTEM_ZLIB will be turned off.")
    set(USE_SYSTEM_ZLIB OFF)
  else()
    include_directories(${ZLIB_INCLUDE_DIRS})
    list(APPEND LIBS ${ZLIB_LIBRARIES})
  endif()
else()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/zlib/CMakeLists.txt")
      add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/zlib)
      include_directories(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/zlib/)
      list(APPEND LIBS "zlibstatic")
    else()
      message(FATAL_ERROR "zlib required target not found!")
  endif()
endif()

if(USE_SYSTEM_MBEDTLS)
  set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
  find_package(MBEDTLS REQUIRED)
  #find_package(MBEDTLS 2.24.0 REQUIRED)
  if(NOT ${MBEDTLS_FOUND})
    message(WARNING "mbedtls target not found! USE_SYSTEM_MBEDTLS will be turned off.")
    set(USE_SYSTEM_MBEDTLS OFF)
  else()
    include_directories(${MBEDTLS_INCLUDE_DIRS})
    
    list(APPEND LIBS "mbedtls")
    list(APPEND LIBS "mbedcrypto")
    list(APPEND LIBS "mbedx509")
    
    #if(NOT ${MBEDTLS_LIBRARIES})
    #  list(APPEND LIBS "mbedtls")
    #  list(APPEND LIBS "mbedcrypto")
    #  list(APPEND LIBS "mbedx509")          
    #else()
    #  list(APPEND LIBS ${MBEDTLS_LIBRARIES})
    #endif()
  endif()
else()
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/MBEDTLS/CMakeLists.txt")
  
add_compile_options(-DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DENABLE_TESTING=OFF)  
  
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/MBEDTLS)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/MBEDTLS/include/)
    list(APPEND LIBS "mbedtls")
    list(APPEND LIBS "mbedcrypto")
    list(APPEND LIBS "mbedx509")
  else()
    message(FATAL_ERROR "mbedtls required target not found!")
  endif()
endif()

if(USE_SYSTEM_UTHASH)
  set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
  find_package(UTHASH)
  if(NOT ${UTHASH_FOUND})
    message(WARNING "mbedtls target not found! USE_SYSTEM_UTHASH will be turned off.")
    set(USE_SYSTEM_UTHASH OFF)
  else()
    include_directories(${UTHASH_INCLUDE_DIRS})
    endif()
else()
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/UTHASH/src/uthash.h")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/uthash/src/)
  else()
    message(FATAL_ERROR "uthash required target not found!")
  endif()
endif()

#
# Compiler settings.
#

if(NOT ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "arm64"))
add_compile_options(-masm=intel -march=native)
endif()
add_compile_options(-Wall -Wextra -Werror-implicit-function-declaration -Wno-unused-function -Wno-unused-label)

# just install libasan6 (or w/e) then flip this ON
set(ENABLE_ASAN OFF)
if(ENABLE_ASAN)
	add_compile_options(-ggdb -O0)
	set(ASAN_FLAGS -fsanitize=address)
	add_compile_options(${ASAN_FLAGS})
	add_link_options(${ASAN_FLAGS})
endif()

if(WIN32)
	add_compile_definitions(WIN32 _WIN32)
	add_compile_definitions(WIN32_LEAN_AND_MEAN)
	add_compile_definitions(NOMINMAX)
endif()

if(UNIX OR MSYS)
	add_compile_definitions(_GNU_SOURCE)
endif()

add_compile_definitions(
	$<$<CONFIG:DEBUG>:_DEBUG>
	$<$<CONFIG:RELEASE>:NDEBUG>
)

#
# Project settings.
#

file(GLOB SRCS "src/*.c")
if(MINGW)
	file(GLOB MINGW_SRCS "src/mingw/*.c")
	list(APPEND SRCS ${MINGW_SRCS})
endif()
include_directories(src)

add_executable(pkg_pfs_tool ${SRCS})
target_link_libraries(pkg_pfs_tool ${LIBS})