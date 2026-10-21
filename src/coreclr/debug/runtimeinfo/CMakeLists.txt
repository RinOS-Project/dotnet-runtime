set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(RUNTIMEINFO_SOURCES
    runtimeinfo.cpp
)

add_library_clr(runtimeinfo STATIC ${RUNTIMEINFO_SOURCES})

function(generate_module_index Target ModuleIndexFile)
    # Win32 may be false when cross compiling
    if (CLR_CMAKE_TARGET_RINOS)
        set(module_index_generator "cmake")
    elseif (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        set(scriptExt ".cmd")
    else()
        set(scriptExt ".sh")
    endif()

    if (module_index_generator STREQUAL "cmake")
        add_custom_command(
            OUTPUT ${ModuleIndexFile}
            COMMAND "${CMAKE_COMMAND}"
                    "-DMODULE=$<TARGET_FILE:${Target}>"
                    "-DOUTPUT=${ModuleIndexFile}"
                    "-DREADELF=${CMAKE_READELF}"
                    -P "${CMAKE_CURRENT_LIST_DIR}/GenerateModuleIndex.cmake"
            DEPENDS ${Target}
            COMMENT "Generating ${Target} module index file -> ${ModuleIndexFile}"
            VERBATIM
        )
    else()
        add_custom_command(
            OUTPUT ${ModuleIndexFile}
            COMMAND ${CLR_ENG_NATIVE_DIR}/genmoduleindex${scriptExt} $<TARGET_FILE:${Target}> ${ModuleIndexFile} ${CMAKE_READELF}
            DEPENDS ${Target}
            COMMENT "Generating ${Target} module index file -> ${ModuleIndexFile}"
        )
    endif()

    set_source_files_properties(
        ${ModuleIndexFile}
        PROPERTIES GENERATED TRUE
    )

    add_dependencies(runtimeinfo ${Target})
    target_sources(runtimeinfo PRIVATE ${ModuleIndexFile})
endfunction(generate_module_index)

if(NOT DEFINED CLR_CROSS_COMPONENTS_BUILD)
    generate_module_index(coreclr ${CMAKE_CURRENT_BINARY_DIR}/runtimemoduleindex.h)
    generate_module_index(mscordaccore ${CMAKE_CURRENT_BINARY_DIR}/dacmoduleindex.h)
    generate_module_index(mscordbi ${CMAKE_CURRENT_BINARY_DIR}/dbimoduleindex.h)
endif()

# publish runtimeinfo lib
install_clr(TARGETS runtimeinfo DESTINATIONS lib COMPONENT runtime)
