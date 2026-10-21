# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.

if(NOT DEFINED MODULE OR NOT DEFINED OUTPUT OR NOT DEFINED READELF)
  message(FATAL_ERROR "MODULE, OUTPUT, and READELF must be specified")
endif()

execute_process(
  COMMAND "${READELF}" -n "${MODULE}"
  RESULT_VARIABLE readelf_result
  OUTPUT_VARIABLE readelf_output
  ERROR_VARIABLE readelf_error
)
if(NOT readelf_result EQUAL 0)
  message(FATAL_ERROR
    "readelf failed for RinOS runtime module ${MODULE} (exit ${readelf_result}): ${readelf_error}")
endif()

string(REGEX MATCH "Build ID:[ \t]*([0-9A-Fa-f]+)" build_id_match "${readelf_output}")
if(NOT build_id_match)
  message(FATAL_ERROR "RinOS runtime module has no ELF GNU build-id: ${MODULE}")
endif()

set(build_id "${CMAKE_MATCH_1}")
string(LENGTH "${build_id}" build_id_length)
math(EXPR build_id_remainder "${build_id_length} % 2")
if(build_id_length LESS 2 OR build_id_remainder OR build_id_length GREATER 46)
  message(FATAL_ERROR
    "RinOS runtime module build-id must contain 1..23 bytes: ${MODULE} (${build_id})")
endif()

math(EXPR build_id_bytes "${build_id_length} / 2")
set(index "0x${build_id_bytes}, ")
math(EXPR last_pair "${build_id_length} - 2")
foreach(offset RANGE 0 ${last_pair} 2)
  string(SUBSTRING "${build_id}" ${offset} 2 pair)
  string(APPEND index "0x${pair}, ")
endforeach()

file(WRITE "${OUTPUT}" "${index}\n")
