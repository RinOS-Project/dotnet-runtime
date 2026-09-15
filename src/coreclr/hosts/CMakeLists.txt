include_directories(inc)

if(CLR_CMAKE_HOST_WIN32 AND NOT CLR_CMAKE_TARGET_RINOS)
  add_subdirectory(coreshim)
endif(CLR_CMAKE_HOST_WIN32 AND NOT CLR_CMAKE_TARGET_RINOS)

if(NOT CLR_CMAKE_TARGET_RINOS)
  add_subdirectory(corerun)
endif()
