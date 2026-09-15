
add_compile_definitions($<${FEATURE_CORECLR_CACHED_INTERFACE_DISPATCH}:FEATURE_CACHED_INTERFACE_DISPATCH>)
add_compile_definitions($<${FEATURE_CORECLR_VIRTUAL_STUB_DISPATCH}:FEATURE_VIRTUAL_STUB_DISPATCH>)

include_directories(${RUNTIME_DIR})

add_subdirectory(daccess)
add_subdirectory(ee)
add_subdirectory(di)
if(FEATURE_INPROC_CRASHREPORT AND NOT CLR_CROSS_COMPONENTS_BUILD)
    add_subdirectory(crashreport)
endif()
# A Windows-hosted RinOS cross build must still produce the target Unix
# createdump. The createdump subdirectory selects its sources from target
# platform variables, so this is not a host utility selection.
if(CLR_CMAKE_HOST_WIN32 OR CLR_CMAKE_TARGET_RINOS)
    add_subdirectory(createdump)
endif(CLR_CMAKE_HOST_WIN32 OR CLR_CMAKE_TARGET_RINOS)
if(FEATURE_SINGLE_FILE_DIAGNOSTICS)
    add_subdirectory(runtimeinfo)
endif(FEATURE_SINGLE_FILE_DIAGNOSTICS)
