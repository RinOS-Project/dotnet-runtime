# Define all the individually buildable components of the CoreCLR build and their respective targets
add_component(jit)
add_component(wasmjit)
add_component(alljits)
add_component(hosts)
add_component(runtime)
add_component(paltests paltests_install)
add_component(iltools)
add_component(nativeaot)
add_component(spmi)
add_component(debug)
add_component(cdac)

# Define coreclr_all as the fallback component and make every component depend on this component.
# iltools and paltests should be minimal subsets, so don't add a dependency on coreclr_misc
set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME coreclr_misc)
add_component(coreclr_misc)
add_dependencies(runtime coreclr_misc)

# The runtime build requires the clrjit build.  ilasm/ildasm are host-side
# build tools in the upstream graph; a RinOS cross build cannot link them as
# target executables until a target C++ ABI/runtime is supplied.  Keep the
# iltools component available for an explicit host build, but do not make it a
# prerequisite of the target runtime aggregate.
if(CLR_CMAKE_TARGET_RINOS)
  add_dependencies(runtime jit)
else()
  add_dependencies(runtime jit iltools)
endif()

# The runtime build requires the debugger tools builds
add_dependencies(runtime debug)

add_dependencies(runtime hosts)
