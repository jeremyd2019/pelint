import pefile
import sys

def align(x, a):
    return x + a - (x % a or a)

pe = pefile.PE(sys.argv[1])
pe.show_warnings()

if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']:
    if not pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE or not pe.has_relocs():
        print("ARM64 image without dynamic base flag or relocations not allowed")

if pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE and not pe.has_relocs():
    print("dynamic base flag set but no relocations, will be ignored")


section_alignment = pe.OPTIONAL_HEADER.SectionAlignment if pe.OPTIONAL_HEADER.SectionAlignment >= 0x1000 else pe.OPTIONAL_HEADER.FileAlignment

expected_next_va = None
for section in pe.sections:
    if expected_next_va is not None and section.VirtualAddress != expected_next_va:
        print("Non-contiguous section %s, virtual address = 0x%08X, size = 0x%08X, expected virtual address = 0x%08X" % (section.Name.decode('ascii'), section.VirtualAddress, section.Misc_VirtualSize, expected_next_va))
    expected_next_va = align(section.VirtualAddress + section.Misc_VirtualSize, section_alignment)


if pe.has_relocs():
    last_va = 0
    for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
        if base_reloc.struct.VirtualAddress < last_va:
            print("Out of order IMAGE_BASE_RELOCATION found, 0x%08X < 0x%08X" % (base_reloc.struct.VirtualAddress, last_va))
        last_va = base_reloc.struct.VirtualAddress

        last_entry_rva = 0
        for entry in base_reloc.entries:
            if entry.type != pefile.RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                if entry.rva < last_entry_rva:
                    print("Out of order relocation entry found, 0x%08X < 0x%08X" % (entry.rva, last_entry_rva))
                last_entry_rva = entry.rva
