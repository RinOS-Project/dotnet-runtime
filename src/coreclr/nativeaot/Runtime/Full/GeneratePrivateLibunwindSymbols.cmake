# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.

if(NOT DEFINED NM_TOOL OR NOT DEFINED OUTPUT OR NOT DEFINED INPUTS)
  message(FATAL_ERROR "NM_TOOL, OUTPUT, and INPUTS must be specified")
endif()

# The caller uses a pipe-separated value so COMMAND_EXPAND_LISTS cannot split
# the -D argument before CMake receives it. Object paths in the runtime build
# are filesystem paths and cannot contain a pipe.
string(REPLACE "|" ";" input_objects "${INPUTS}")
file(WRITE "${OUTPUT}" "")

foreach(object IN LISTS input_objects)
  if(NOT EXISTS "${object}")
    message(FATAL_ERROR "NativeAOT libunwind object does not exist: ${object}")
  endif()

  execute_process(
    COMMAND "${NM_TOOL}" --extern-only --defined-only --format=just-symbols "${object}"
    RESULT_VARIABLE nm_result
    OUTPUT_VARIABLE nm_symbols
    ERROR_VARIABLE nm_error
  )
  if(NOT nm_result EQUAL 0)
    message(FATAL_ERROR
      "nm failed for NativeAOT libunwind object ${object} (exit ${nm_result}): ${nm_error}")
  endif()

  file(APPEND "${OUTPUT}" "${nm_symbols}")
endforeach()
