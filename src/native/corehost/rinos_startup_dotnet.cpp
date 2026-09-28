// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/* dotnet.cpp is C++, so its main symbol uses C++ linkage on the freestanding
 * RinOS target. Keep the process crt0 ABI itself C-linkage and bridge only the
 * application entry here. */
extern int main(int argc, const char* argv[]);

extern "C" int __app_main(int argc, char** argv, char** envp)
{
    const char* const* const_argv =
        reinterpret_cast<const char* const*>(argv);
    (void)envp;
    return main(argc, const_cast<const char**>(const_argv));
}
