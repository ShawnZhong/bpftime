cmake_minimum_required(VERSION 3.15)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  cmake_policy(SET CMP0135 NEW)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fno-omit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lncurses")


# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++ -lc++abi")
# set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -stdlib=libc++ -lc++abi")
#
# Project details
#
project(
  "bpftime"
  VERSION 0.1.0
  LANGUAGES C CXX
)

#
# Set project options
#
include(cmake/CompilerWarnings.cmake)
include(cmake/StandardSettings.cmake)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

get_filename_component(CMAKE_AR_NAME "${CMAKE_AR}" NAME)
function(bpftime_add_static_lib_component_command target)
  if(APPLE)
    if(CMAKE_AR_NAME STREQUAL "ar")
      list(APPEND CMDS
        COMMAND ${CMAKE_COMMAND} -E make_directory objs/${target}
        COMMAND bash ${CMAKE_SOURCE_DIR}/cmake/extract_and_rename.sh $<TARGET_FILE:${target}> objs/${target}
      )
      set(BPFTIME_STATIC_LIB_AR_CMDS ${BPFTIME_STATIC_LIB_AR_CMDS} ${CMDS} PARENT_SCOPE)
    else()
      message(ERROR " CMAKE_AR is not `ar`. Only archiving with `ar` is supported.")
    endif()
  else()
    list(APPEND CMDS
      COMMAND ${CMAKE_COMMAND} -E make_directory objs/${target}
      COMMAND bash ${CMAKE_SOURCE_DIR}/cmake/extract_and_rename.sh $<TARGET_FILE:${target}> objs/${target}
    )
    set(BPFTIME_STATIC_LIB_AR_CMDS ${BPFTIME_STATIC_LIB_AR_CMDS} ${CMDS} PARENT_SCOPE)
  endif()

  set(BPFTIME_STATIC_LIB_DEPS ${BPFTIME_STATIC_LIB_DEPS} ${target} PARENT_SCOPE)
endfunction()

function(bpftime_add_libs_component_command target_path)
  get_filename_component(target_name ${target_path} NAME)
  string(REGEX REPLACE "^lib" "" target_name ${target_name})
  string(REGEX REPLACE "\.a$" "" target_name ${target_name})

  if(APPLE)
    if(CMAKE_AR_NAME STREQUAL "ar")
      list(APPEND CMDS
        COMMAND ${CMAKE_COMMAND} -E make_directory objs/${target_name}
        COMMAND ${CMAKE_COMMAND} -E env bash ${CMAKE_SOURCE_DIR}/cmake/extract_and_rename.sh ${target_path} ${CMAKE_BINARY_DIR}/objs/${target_name}
      )
      set(BPFTIME_STATIC_LLVM_LIB_AR_CMDS ${BPFTIME_STATIC_LLVM_LIB_AR_CMDS} ${CMDS} PARENT_SCOPE)
    else()
      message(ERROR " CMAKE_AR is not `ar`. Only archiving with `ar` is supported.")
    endif()
  else()
    list(APPEND CMDS
      COMMAND ${CMAKE_COMMAND} -E make_directory objs/${target_name}
      COMMAND ${CMAKE_COMMAND} -E env bash ${CMAKE_SOURCE_DIR}/cmake/extract_and_rename.sh ${target_path} ${CMAKE_BINARY_DIR}/objs/${target_name}
    )
    set(BPFTIME_STATIC_LLVM_LIB_AR_CMDS ${BPFTIME_STATIC_LLVM_LIB_AR_CMDS} ${CMDS} PARENT_SCOPE)
  endif()
endfunction()

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
  message(STATUS "Enabling ubsan for Debug builds; Processor=${CMAKE_SYSTEM_PROCESSOR}")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")

  if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm((32.*)|(v6.*)|(v7.*))")
    message(STATUS "Linking libatomic on arm32 machines..")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -latomic")
  endif()
endif()

message(STATUS "Started CMake for ${PROJECT_NAME} v${PROJECT_VERSION}...\n")

# if option to build without libbpf is set
if(${BPFTIME_BUILD_WITH_LIBBPF})
  add_definitions(-DBPFTIME_BUILD_WITH_LIBBPF=1)
endif()

if(UNIX)
  add_compile_options("$<$<CONFIG:DEBUG>:-D_DEBUG>") # this will allow to use same _DEBUG macro available in both Linux as well as Windows - MSCV environment. Easy to put Debug specific code.
endif(UNIX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)

#
# Setup alternative names
#
if(${PROJECT_NAME}_USE_ALT_NAMES)
  string(TOLOWER ${PROJECT_NAME} PROJECT_NAME_LOWERCASE)
  string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UPPERCASE)
else()
  set(PROJECT_NAME_LOWERCASE ${PROJECT_NAME})
  set(PROJECT_NAME_UPPERCASE ${PROJECT_NAME})
endif()

#
# Prevent building in the source directory
#
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there.\n")
endif()

if(${BPFTIME_BUILD_WITH_LIBBPF})
  include(cmake/libbpf.cmake)
endif()

# install frida
include(cmake/frida.cmake)

set(CMAKE_POSITION_INDEPENDENT_CODE YES)

if(${ENABLE_EBPF_VERIFIER})
  add_subdirectory(bpftime-verifier)
else()
  message(STATUS "Skipping ebpf verifier")

  # Catch2
  if(NOT DEFINED Catch2_INCLUDE)
    message(STATUS "Adding Catch2 by subdirectory")
    add_subdirectory(third_party/Catch2)
  endif()
endif()

# spdlog
add_subdirectory(third_party/spdlog)

if(NOT DEFINED SPDLOG_ACTIVE_LEVEL)
  add_compile_definitions(SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_TRACE)
  message(STATUS "Setting SPDLOG_ACTIVE_LEVEL to SPDLOG_LEVEL_TRACE")
else()
  add_compile_definitions(SPDLOG_ACTIVE_LEVEL=${SPDLOG_ACTIVE_LEVEL})
  message(STATUS "Setting SPDLOG_ACTIVE_LEVEL to ${SPDLOG_ACTIVE_LEVEL}")
endif()

set(SPDLOG_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/spdlog/include)

if(BPFTIME_ENABLE_CUDA_ATTACH)
  add_compile_definitions(BPFTIME_ENABLE_CUDA_ATTACH=1)
endif()

# argparse
add_subdirectory(third_party/argparse)

# main library
add_subdirectory(vm)

add_subdirectory(attach)

add_subdirectory(runtime)

# option to use probe read/write checks
if(ENABLE_PROBE_READ_CHECK)
  target_compile_definitions(runtime PRIVATE ENABLE_PROBE_READ_CHECK=1)
endif()

if(ENABLE_PROBE_WRITE_CHECK)
  target_compile_definitions(runtime PRIVATE ENABLE_PROBE_WRITE_CHECK=1)
endif()

# add to single archive if option is enabled
if(${BPFTIME_BUILD_STATIC_LIB})
  if(${BPFTIME_UBPF_JIT})
    set(UBPF_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/vm/compat/ubpf-vm)
  endif()
  if(${BPFTIME_LLVM_JIT})
    set(LLVM_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/vm/compat/llvm-vm)
  endif()
  message(STATUS " Adding libraries to single static archive file")
  bpftime_add_static_lib_component_command(bpftime_vm)

  if(${BPFTIME_LLVM_JIT})
    bpftime_add_static_lib_component_command(bpftime_llvm_vm)
    bpftime_add_libs_component_command(${LLVM_BUILD_DIR}/libbpftime_llvm_vm.a)
    message(STATUS " Adding LLVM JIT to static archive")
  endif()

  if(${BPFTIME_UBPF_JIT})
    bpftime_add_static_lib_component_command(bpftime_ubpf_vm)
    bpftime_add_libs_component_command(${UBPF_BUILD_DIR}/ubpf/lib/libubpf.a)
    bpftime_add_libs_component_command(${UBPF_BUILD_DIR}/libbpftime_ubpf_vm.a)
    message(STATUS " Adding uBPF JIT to static archive")
  endif()


  bpftime_add_libs_component_command(${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a)
  bpftime_add_static_lib_component_command(bpftime_frida_uprobe_attach_impl)

  if(${BPFTIME_BUILD_WITH_LIBBPF})
    bpftime_add_libs_component_command(${CMAKE_CURRENT_BUILD_DIR}libbpf/libbpf/libbpf.a)
    bpftime_add_static_lib_component_command(bpftime_syscall_trace_attach_impl)
  endif()

  bpftime_add_static_lib_component_command(runtime)
  bpftime_add_static_lib_component_command(spdlog)
  add_custom_command(OUTPUT "libbpftime.a"
    ${BPFTIME_STATIC_LIB_AR_CMDS}
    ${BPFTIME_STATIC_LLVM_LIB_AR_CMDS}
    COMMAND ${CMAKE_AR} -qcs libbpftime.a objs/*/*.o
    COMMAND ${CMAKE_COMMAND} -E remove_directory objs
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${BPFTIME_STATIC_LIB_DEPS}
  )
  add_custom_target(bpftime_static_target ALL DEPENDS "libbpftime.a")
  add_library(bpftime_static STATIC IMPORTED GLOBAL)
  add_dependencies(bpftime_static bpftime_static_target)

  set_target_properties(bpftime_static
    PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/libbpftime.a"
  )

  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libbpftime.a
    DESTINATION ~/.bpftime
  )
endif()

if(${BUILD_BPFTIME_DAEMON} AND ${BPFTIME_BUILD_WITH_LIBBPF})
  add_subdirectory(daemon)
endif()

add_subdirectory(tools)

if(${BUILD_ATTACH_IMPL_EXAMPLE})
  add_subdirectory(example/attach_implementation)
endif()

# benchmark that requires bpftime libraries
if(${BPFTIME_BUILD_WITH_LIBBPF})
  # Currently benchmark is using libbpf
  add_subdirectory(benchmark)
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

set(DEST_DIR "$ENV{HOME}/.bpftime")

if(${BPFTIME_BUILD_WITH_LIBBPF})
  install(TARGETS bpftime-agent bpftime_text_segment_transformer bpftime-syscall-server CONFIGURATIONS Release Debug RelWithDebInfo DESTINATION ${DEST_DIR})
else()
  install(TARGETS bpftime-agent bpftime-syscall-server CONFIGURATIONS Release Debug RelWithDebInfo DESTINATION ${DEST_DIR})
endif()

# add_subdirectory(./example/mix-schedule-mnist/cpu)
