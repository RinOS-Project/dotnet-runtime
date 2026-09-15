
add_compile_definitions($<${FEATURE_CORECLR_CACHED_INTERFACE_DISPATCH}:FEATURE_CACHED_INTERFACE_DISPATCH>)
add_compile_definitions($<${FEATURE_CORECLR_VIRTUAL_STUB_DISPATCH}:FEATURE_VIRTUAL_STUB_DISPATCH>)

include_directories(${RUNTIME_DIR})

add_subdirectory(daccess)
add_subdirectory(ee)
add_subdirectory(di)
if(FEATURE_INPROC_CRASHREPORT AND NOT CLR_CROSS_COMPONENTS_BUILD)
    add_subdirectory(crashreport)
endif()
# createdump depends on the host Unix ptrace/procfs ABI. RinOS has no
# compatible ptrace contract yet, so keep the utility out of target builds
# until a product-owned crash-dump ABI is connected.
if(CLR_CMAKE_HOST_WIN32 AND NOT CLR_CMAKE_TARGET_RINOS)
    add_subdirectory(createdump)
endif(CLR_CMAKE_HOST_WIN32 AND NOT CLR_CMAKE_TARGET_RINOS)
if(FEATURE_SINGLE_FILE_DIAGNOSTICS)
    add_subdirectory(runtimeinfo)
endif(FEATURE_SINGLE_FILE_DIAGNOSTICS)
