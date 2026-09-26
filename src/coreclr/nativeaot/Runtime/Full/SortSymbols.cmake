# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.

if(NOT DEFINED INPUT OR NOT DEFINED OUTPUT)
  message(FATAL_ERROR "INPUT and OUTPUT must be specified")
endif()

file(STRINGS "${INPUT}" symbols)
list(REMOVE_DUPLICATES symbols)
list(SORT symbols)

file(WRITE "${OUTPUT}" "")
foreach(symbol IN LISTS symbols)
  file(APPEND "${OUTPUT}" "${symbol}\n")
endforeach()
