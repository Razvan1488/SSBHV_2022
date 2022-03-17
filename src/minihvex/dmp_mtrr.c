#include "dmp_mtrr.h"
#include "log.h"
#include "data.h"

STATUS
DumpMtrrData(
    IN      MTRR_DATA*     MtrrData
    )
{
    if (MtrrData == NULL) return STATUS_INVALID_PARAMETER1;

    LOG( "MTRR List dump: \n");

    // TODO: perform implementation here
    for (DWORD i = 0; i < MtrrData->NumberOfListEntries; i++)
    {
        LOG("First line in for %U : \n", i);
        LIST_ITERATOR it;
        LIST_ENTRY dummyEntry = MtrrData->MtrrRegions[i];
        const PLIST_ENTRY entry = &dummyEntry;
        ListIteratorInit(entry, &it);
        LOG("Before while %U : \n", i + 1);
        PLIST_ENTRY pEntry;
        while ((pEntry = ListIteratorNext(&it)) != NULL)
        {
            LOG("In while %U : \n", i + 2);
            PMTRR_ENTRY pMtrrEntry = CONTAINING_RECORD(pEntry, MTRR_ENTRY, ListEntry);
            LOGPL("Memory type %b, memory range %U -> %U \n", pMtrrEntry->MemoryType, pMtrrEntry->BaseAddress, pMtrrEntry->EndAddress);
        }
    }

    return STATUS_SUCCESS;
}
