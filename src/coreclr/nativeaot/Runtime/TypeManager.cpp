// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#include "common.h"
#include "CommonTypes.h"
#include "CommonMacros.h"
#include "daccess.h"
#include "PalLimitedContext.h"
#include "Pal.h"
#include "holder.h"
#include "rhassert.h"
#include "slist.h"
#include "shash.h"
#include "rhbinder.h"
#include "regdisplay.h"
#include "StackFrameIterator.h"
#include "thread.h"
#include "event.h"
#include "threadstore.h"
#include "TypeManager.h"

/* static */
TypeManager * TypeManager::Create(HANDLE osModule, void * pModuleHeader, void** pClasslibFunctions, uint32_t nClasslibFunctions)
{
    ReadyToRunHeader * pReadyToRunHeader = (ReadyToRunHeader *)pModuleHeader;

    // Sanity check the signature magic
    ASSERT(pReadyToRunHeader->Signature == ReadyToRunHeaderConstants::Signature);
    if (pReadyToRunHeader->Signature != ReadyToRunHeaderConstants::Signature)
        return nullptr;

    // Only the current version is supported currently
    ASSERT((pReadyToRunHeader->MajorVersion == ReadyToRunHeaderConstants::CurrentMajorVersion) &&
           (pReadyToRunHeader->MinorVersion == ReadyToRunHeaderConstants::CurrentMinorVersion));

    if ((pReadyToRunHeader->MajorVersion != ReadyToRunHeaderConstants::CurrentMajorVersion) ||
        (pReadyToRunHeader->MinorVersion != ReadyToRunHeaderConstants::CurrentMinorVersion))
        return nullptr;

    if (pReadyToRunHeader->EntrySize != sizeof(ModuleInfoRow))
        return nullptr;

    return new (nothrow) TypeManager(osModule, pReadyToRunHeader, pClasslibFunctions, nClasslibFunctions);
}

TypeManager::TypeManager(HANDLE osModule, ReadyToRunHeader * pHeader, void** pClasslibFunctions, uint32_t nClasslibFunctions)
    : m_osModule(osModule), m_pHeader(pHeader),
      m_sectionsSorted(true),
      m_pClasslibFunctions(pClasslibFunctions), m_nClasslibFunctions(nClasslibFunctions)
{
    int length;
    ModuleInfoRow* pModuleInfoRows = (ModuleInfoRow*)(m_pHeader + 1);
    for (int i = 1; i < m_pHeader->NumberOfSections; i++)
    {
        if (pModuleInfoRows[i - 1].SectionId >= pModuleInfoRows[i].SectionId)
        {
            m_sectionsSorted = false;
            break;
        }
    }

    m_pStaticsGCDataSection = (uint8_t*)GetModuleSection(ReadyToRunSectionType::GCStaticRegion, &length);
    m_pThreadStaticsDataSection = (uint8_t*)GetModuleSection(ReadyToRunSectionType::ThreadStaticRegion, &length);
}

void * TypeManager::GetModuleSection(ReadyToRunSectionType sectionId, int * length)
{
    ModuleInfoRow * pModuleInfoRows = (ModuleInfoRow *)(m_pHeader + 1);

    auto returnValidatedSection = [length](ModuleInfoRow* section) -> void*
    {
        // A malformed externally-produced header must not publish a wrapped
        // length or a non-empty section with no backing address to managed
        // startup code. Treat both cases as an absent section.
        if (section->Length < 0 ||
            (section->Length != 0 && section->Start == nullptr))
        {
            *length = 0;
            return nullptr;
        }

        *length = section->Length;
        return section->Start;
    };

    ASSERT(m_pHeader->EntrySize == sizeof(ModuleInfoRow));

    if (m_sectionsSorted)
    {
        // ReadyToRunHeaderNode emits section rows sorted by ID.
        int low = 0;
        int high = m_pHeader->NumberOfSections;
        while (low < high)
        {
            int middle = low + (high - low) / 2;
            ModuleInfoRow* pCurrent = pModuleInfoRows + middle;
            if ((int32_t)sectionId == pCurrent->SectionId)
                return returnValidatedSection(pCurrent);
            if (pCurrent->SectionId < (int32_t)sectionId)
                low = middle + 1;
            else
                high = middle;
        }
        *length = 0;
        return nullptr;
    }

    // Preserve lookup behavior for externally produced headers without the
    // ordering emitted by the supported NativeAOT compiler.
    for (int i = 0; i < m_pHeader->NumberOfSections; i++)
    {
        ModuleInfoRow * pCurrent = pModuleInfoRows + i;
        if ((int32_t)sectionId == pCurrent->SectionId)
            return returnValidatedSection(pCurrent);
    }

    *length = 0;
    return nullptr;
}

void * TypeManager::GetClasslibFunction(ClasslibFunctionId functionId)
{
    uint32_t id = (uint32_t)functionId;

    if (id >= m_nClasslibFunctions)
        return nullptr;

    return m_pClasslibFunctions[id];
}

HANDLE TypeManager::GetOsModuleHandle()
{
    return m_osModule;
}

TypeManager* TypeManagerHandle::AsTypeManager()
{
    return (TypeManager*)_value;
}
