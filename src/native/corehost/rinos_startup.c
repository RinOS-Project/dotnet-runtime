// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * The RinOS user process crt0 calls the application through __app_main and
 * provides the process argv/environment contract before running C++ static
 * initialization. Corehost is normally linked by a hosted platform startup
 * object, but the RinOS target is deliberately freestanding, so provide the
 * small ABI bridge that the shared RinOS crt0 needs.
 */

typedef void (*rinos_startup_callback)(void);

extern rinos_startup_callback __init_array_start[];
extern rinos_startup_callback __init_array_end[];
extern rinos_startup_callback __fini_array_start[];
extern rinos_startup_callback __fini_array_end[];
extern void __cxa_finalize(void* dso_handle);
void* __dso_handle;
char** environ;
int __rin_argc;
char** __rin_argv;
char** __rin_envp;

void __rin_init_process_context(int argc, char** argv, char** envp)
{
    __rin_argc = argc;
    __rin_argv = argv;
    __rin_envp = envp;
    environ = envp;
}

void __cxx_global_constructors(void)
{
    rinos_startup_callback* callback;
    for (callback = __init_array_start; callback < __init_array_end; ++callback)
    {
        if (*callback != 0)
        {
            (*callback)();
        }
    }
}

void __cxx_global_destructors(void)
{
    rinos_startup_callback* callback;
    __cxa_finalize(0);
    callback = __fini_array_end;
    while (callback != __fini_array_start)
    {
        --callback;
        if (*callback != 0)
        {
            (*callback)();
        }
    }
}

#if !defined(RINOS_COREHOST_DOTNET)
extern int main(int argc, char** argv);

int __app_main(int argc, char** argv, char** envp)
{
    (void)envp;
    return main(argc, argv);
}
#endif
