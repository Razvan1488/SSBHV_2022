#include "ept.h"
#include "hv_heap.h"
#include "data.h"
#include "log.h"


static void map_pdpt(PEPT_PML4_ENTRY pml4_entry, PEPT_PDPT_ENTRY_PD pdpt_entry_pd, QWORD index_pml4, BYTE RwxAccess);
static void map_pd(PEPT_PDPT_ENTRY_PD pdpt_entry_pd, PEPT_PD_ENTRY_PT pd_entry_pt, QWORD index_pdpt, BYTE RwxAccess);
static void map_pt(PEPT_PD_ENTRY_PT pd_entry_pt, PEPT_PT_ENTRY pt_entry, QWORD index, BYTE RwxAccess);
static void map_pt_entry(PEPT_PT_ENTRY pt_entry, QWORD index_pt, PHYSICAL_ADDRESS HostPhysicalAddress, BYTE RwxAccess, BYTE MemoryType);
static PEPT_PDPT_ENTRY_PD alloc_and_map_pdpt(PEPT_PML4_ENTRY pml4_entry, QWORD index_pml4, BYTE RwxAccess);
static PEPT_PD_ENTRY_PT alloc_and_map_pd(PEPT_PDPT_ENTRY_PD pdpt_entry_pd, QWORD index_pdpt, BYTE RwxAccess);
static PEPT_PT_ENTRY alloc_and_map_pt(PEPT_PD_ENTRY_PT pd_entry_pt, QWORD index_pd, BYTE RwxAccess);

STATUS EptInit(OUT PEPTP* Ept)
{
	*Ept = HvAllocPoolWithTag(PoolAllocateZeroMemory, sizeof(EPTP), HEAP_PAGE_TAG, 0);
	if (*Ept == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	PEPT_PML4_ENTRY pml4_entry = gGlobalData.pml4_entry;
	LOG("In EptInit \n");
	(*Ept)->PhysicalAddress = (VA2PA(pml4_entry)) >> SHIFT_FOR_EPT_PHYSICAL_ADDR; LOG("In EptInit : Ept->PhysicalAddress 0x%X \n", (*Ept)->PhysicalAddress);
	(*Ept)->MemoryType = MEMORY_TYPE_STRONG_UNCACHEABLE;
	(*Ept)->ActivateAccessedAndDirty = 0;
	(*Ept)->PageWalkLength = 3;
	(*Ept)->Reserved0 = 0;
	(*Ept)->Reserved1 = 0;

	return STATUS_SUCCESS;
}

STATUS EptMapGPA(INOUT EPTP* Ept, IN PHYSICAL_ADDRESS GuestPhysicalAddress, IN DWORD SizeInBytes, IN BYTE MemoryType, IN PHYSICAL_ADDRESS HostPhysicalAddress, IN BYTE RwxAccess, IN BOOLEAN Invalidate)
{
	UNREFERENCED_PARAMETER(SizeInBytes);
	PEPT_PML4_ENTRY pml4_entry = gGlobalData.pml4_entry;
	QWORD guestPhysicalAddress = (QWORD)GuestPhysicalAddress;

	//Get index in tables
	QWORD index_pml4 = MASK_EPT_PML4_OFFSET(guestPhysicalAddress);
	QWORD index_pdpt = MASK_EPT_PDPTE_OFFSET(guestPhysicalAddress);
	QWORD index_pd = MASK_EPT_PDE_OFFSET(guestPhysicalAddress);
	QWORD index_pt = MASK_EPT_PTE_OFFSET(guestPhysicalAddress);

	//Pointers to tables
	PEPT_PDPT_ENTRY_PD pdpt_entry_pd = NULL;
	PEPT_PD_ENTRY_PT pd_entry_pt = NULL;
	PEPT_PT_ENTRY pt_entry = NULL;

	//Process pml4
	if (pml4_entry[index_pml4].PhysicalAddress == 0) //No entry at that address
	{
		pdpt_entry_pd = alloc_and_map_pdpt(pml4_entry, index_pml4, RwxAccess);
		if (pdpt_entry_pd == NULL)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}
	else // pml4 mapped, search for the other tables
	{
		pdpt_entry_pd = (PEPT_PDPT_ENTRY_PD)((pml4_entry + index_pml4)->PhysicalAddress << SHIFT_FOR_EPT_PHYSICAL_ADDR);
	}

	//Process pdpt
	if (pdpt_entry_pd[index_pdpt].PhysicalAddress == 0)
	{
		pd_entry_pt = alloc_and_map_pd(pdpt_entry_pd, index_pdpt, RwxAccess);
		if (pd_entry_pt == NULL)
		{
			LOG("Failed alloc PD_entry");
			return STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		//get PD address
		pd_entry_pt = (PEPT_PD_ENTRY_PT)((pdpt_entry_pd + index_pdpt)->PhysicalAddress << SHIFT_FOR_EPT_PHYSICAL_ADDR);
	}

	if (pd_entry_pt[index_pd].PhysicalAddress == 0)
	{
		pt_entry = alloc_and_map_pt(pd_entry_pt, index_pd, RwxAccess);
		if (pt_entry == NULL)
		{
			LOG("Failed alloc PT_entry");
			return STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		//Get PT address
		pt_entry = (PEPT_PT_ENTRY)((pd_entry_pt + index_pd)->PhysicalAddress << SHIFT_FOR_EPT_PHYSICAL_ADDR);
	}

	if (pt_entry[index_pt].PhysicalAddress == 0)
	{
		map_pt_entry(pt_entry, index_pt, HostPhysicalAddress, RwxAccess, MemoryType);
	}
	else
	{
		LOG("Address already mapped 0x%X", guestPhysicalAddress);
	}

	return STATUS_SUCCESS;
}

static PEPT_PDPT_ENTRY_PD alloc_and_map_pdpt(PEPT_PML4_ENTRY pml4_entry, QWORD index_pml4, BYTE RwxAccess)
{
	PEPT_PDPT_ENTRY_PD pdpt_entry_pd = HvAllocPoolWithTag(PoolAllocateZeroMemory, PAGE_SIZE, HEAP_PAGE_TAG, PAGE_SIZE); // alloc pdpt entry
	if (pdpt_entry_pd == NULL)
	{
		LOG("PDPT alloc failed \n");
		return NULL;
	}
	map_pdpt(pml4_entry, pdpt_entry_pd, index_pml4, RwxAccess);

	return pdpt_entry_pd;
}

static PEPT_PD_ENTRY_PT alloc_and_map_pd(PEPT_PDPT_ENTRY_PD pdpt_entry_pd, QWORD index_pdpt, BYTE RwxAccess)
{
	PEPT_PD_ENTRY_PT pd_entry_pt = HvAllocPoolWithTag(PoolAllocateZeroMemory, PAGE_SIZE, HEAP_PAGE_TAG, PAGE_SIZE);
	if (pd_entry_pt == NULL)
	{
		LOG("PD alloc failed \n");
		return NULL;
	}
	map_pd(pdpt_entry_pd, pd_entry_pt, index_pdpt, RwxAccess);

	return pd_entry_pt;
}

static PEPT_PT_ENTRY alloc_and_map_pt(PEPT_PD_ENTRY_PT pd_entry_pt, QWORD index_pd, BYTE RwxAccess)
{
	PEPT_PT_ENTRY pt_entry = HvAllocPoolWithTag(PoolAllocateZeroMemory, PAGE_SIZE, HEAP_PAGE_TAG, PAGE_SIZE);
	if (pt_entry == NULL)
	{
		LOG("Failed alloc PT_entry");
		return NULL;
	}
	map_pt(pd_entry_pt, pt_entry, index_pd, RwxAccess);

	return pt_entry;
}

static void map_pdpt(PEPT_PML4_ENTRY pml4_entry, PEPT_PDPT_ENTRY_PD pdpt_entry_pd, QWORD index_pml4, BYTE RwxAccess)
{
	pml4_entry[index_pml4].Accessed = 1;
	pml4_entry[index_pml4].Execute = IsBooleanFlagOn(RwxAccess, EPT_EXEC_ACCESS);
	pml4_entry[index_pml4].Ignored0 = 0;
	pml4_entry[index_pml4].Ignored1 = 0;
	pml4_entry[index_pml4].PhysicalAddress = (VA2PA(pdpt_entry_pd)) >> SHIFT_FOR_EPT_PHYSICAL_ADDR;
	pml4_entry[index_pml4].Read = IsBooleanFlagOn(RwxAccess, EPT_READ_ACCESS);
	pml4_entry[index_pml4].Reserved0 = 0;
	pml4_entry[index_pml4].Write = IsBooleanFlagOn(RwxAccess, EPT_WRITE_ACCESS);
}

static void map_pd(PEPT_PDPT_ENTRY_PD pdpt_entry_pd, PEPT_PD_ENTRY_PT pd_entry_pt, QWORD index_pdpt, BYTE RwxAccess)
{
	pdpt_entry_pd[index_pdpt].Accessed = 1;
	pdpt_entry_pd[index_pdpt].Execute = IsBooleanFlagOn(RwxAccess, EPT_EXEC_ACCESS);
	pdpt_entry_pd[index_pdpt].Ignored0 = 0;
	pdpt_entry_pd[index_pdpt].Ignored1 = 0;
	pdpt_entry_pd[index_pdpt].PhysicalAddress = (VA2PA(pd_entry_pt)) >> SHIFT_FOR_EPT_PHYSICAL_ADDR;
	pdpt_entry_pd[index_pdpt].Read = IsBooleanFlagOn(RwxAccess, EPT_READ_ACCESS);
	pdpt_entry_pd[index_pdpt].Reserved0 = 0;
	pdpt_entry_pd[index_pdpt].Write = IsBooleanFlagOn(RwxAccess, EPT_WRITE_ACCESS);
}

static void map_pt(PEPT_PD_ENTRY_PT pd_entry_pt, PEPT_PT_ENTRY pt_entry, QWORD index_pd, BYTE RwxAccess)
{
	pd_entry_pt[index_pd].Accessed = 1;
	pd_entry_pt[index_pd].Execute = IsBooleanFlagOn(RwxAccess, EPT_EXEC_ACCESS);
	pd_entry_pt[index_pd].Ignored0 = 0;
	pd_entry_pt[index_pd].Ignored1 = 0;
	pd_entry_pt[index_pd].PhysicalAddress = (VA2PA(pt_entry)) >> SHIFT_FOR_EPT_PHYSICAL_ADDR;
	pd_entry_pt[index_pd].Read = IsBooleanFlagOn(RwxAccess, EPT_READ_ACCESS);
	pd_entry_pt[index_pd].Reserved0 = 0;
	pd_entry_pt[index_pd].Write = IsBooleanFlagOn(RwxAccess, EPT_WRITE_ACCESS);
}

static void map_pt_entry(PEPT_PT_ENTRY pt_entry, QWORD index_pt, PHYSICAL_ADDRESS HostPhysicalAddress, BYTE RwxAccess, BYTE MemoryType)
{
	pt_entry[index_pt].Accessed = 1;
	pt_entry[index_pt].Dirty = 0;
	pt_entry[index_pt].Execute = IsBooleanFlagOn(RwxAccess, EPT_EXEC_ACCESS);
	pt_entry[index_pt].Ignored0 = 0;
	pt_entry[index_pt].Ignored1 = 0;
	pt_entry[index_pt].Ignored2 = 0;
	pt_entry[index_pt].IgnorePAT = 0;
	pt_entry[index_pt].MemoryType = MemoryType;
	pt_entry[index_pt].PhysicalAddress = ((QWORD)HostPhysicalAddress) >> SHIFT_FOR_EPT_PHYSICAL_ADDR;
	pt_entry[index_pt].Read = IsBooleanFlagOn(RwxAccess, EPT_READ_ACCESS);
	pt_entry[index_pt].SupressVE = 0;
	pt_entry[index_pt].Write = IsBooleanFlagOn(RwxAccess, EPT_WRITE_ACCESS);
}


PHYSICAL_ADDRESS
EptGetHpaFromGpa(
	IN EPTP* Ept,
	IN PHYSICAL_ADDRESS Gpa
)
{
	PHYSICAL_ADDRESS result;
	QWORD guestPhysicalAddress = (QWORD)Gpa;

	PEPT_PML4_ENTRY pml4_entry = NULL;
	PEPT_PDPT_ENTRY_PD pdpt_entry_pd = NULL;
	PEPT_PD_ENTRY_PT pd_entry_pt = NULL;
	PEPT_PT_ENTRY pt_entry = NULL;

	QWORD index_pml4 = MASK_EPT_PML4_OFFSET(guestPhysicalAddress);
	QWORD index_pdpt = MASK_EPT_PDPTE_OFFSET(guestPhysicalAddress);
	QWORD index_pd = MASK_EPT_PDE_OFFSET(guestPhysicalAddress);
	QWORD index_pt = MASK_EPT_PTE_OFFSET(guestPhysicalAddress);

	LOG("Address to convert: %X and indexes %U %U %U %U\n",(QWORD)Gpa,index_pml4,index_pdpt,index_pd,index_pt);
	pml4_entry = gGlobalData.pml4_entry;
	if (pml4_entry == NULL)
	{
		LOG("No pml4 entry for GPA %U", guestPhysicalAddress);
		return (PHYSICAL_ADDRESS)0;
	}
	pdpt_entry_pd = (PEPT_PDPT_ENTRY_PD)(PA2VA((pml4_entry + index_pml4)->PhysicalAddress << SHIFT_FOR_EPT_PHYSICAL_ADDR));
	if (pdpt_entry_pd == NULL)
	{
		LOG("No pdpt entry for GPA %U", guestPhysicalAddress);
		return (PHYSICAL_ADDRESS)0;
	}
	pd_entry_pt = (PEPT_PD_ENTRY_PT)(PA2VA((pdpt_entry_pd + index_pdpt)->PhysicalAddress << SHIFT_FOR_EPT_PHYSICAL_ADDR));
	if (pd_entry_pt == NULL)
	{
		LOG("No pd entry for GPA %U", guestPhysicalAddress);
		return (PHYSICAL_ADDRESS)0;
	}
	pt_entry = (PEPT_PT_ENTRY)(PA2VA((pd_entry_pt + index_pd)->PhysicalAddress << SHIFT_FOR_EPT_PHYSICAL_ADDR)); // get the addr from PD table
	if (pt_entry == NULL)
	{
		LOG("No pd entry for GPA %U", guestPhysicalAddress);
		return (PHYSICAL_ADDRESS)0;
	}
	result = (PHYSICAL_ADDRESS)((pt_entry[index_pt].PhysicalAddress << SHIFT_FOR_EPT_PHYSICAL_ADDR) + MASK_EPT_PAGE_OFFSET(guestPhysicalAddress) );
	LOG("Converted address %X \n",result);

	return result;
}


