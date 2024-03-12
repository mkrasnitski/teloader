from binaryninja import BinaryView, Type, NamedTypeReferenceType

from .teconstants import *

def define_named_type(bv: BinaryView, name: str, ty: Type) -> NamedTypeReferenceType:
    type_name = bv.define_type(Type.generate_auto_type_id("te", name), name, ty)
    return Type.named_type_from_type(type_name, ty)

def define_te_header_type(bv: BinaryView) -> NamedTypeReferenceType:
    machine_type = Type.enumeration(arch=bv.arch, width=2, sign=False, members=[
        ("IMAGE_FILE_MACHINE_UNKNOWN", IMAGE_FILE_MACHINE_UNKNOWN),
        ("IMAGE_FILE_MACHINE_AM33", IMAGE_FILE_MACHINE_AM33),
        ("IMAGE_FILE_MACHINE_AMD64", IMAGE_FILE_MACHINE_AMD64),
        ("IMAGE_FILE_MACHINE_ARM", IMAGE_FILE_MACHINE_ARM),
        ("IMAGE_FILE_MACHINE_ARM64", IMAGE_FILE_MACHINE_ARM64),
        ("IMAGE_FILE_MACHINE_ARMNT", IMAGE_FILE_MACHINE_ARMNT),
        ("IMAGE_FILE_MACHINE_EBC", IMAGE_FILE_MACHINE_EBC),
        ("IMAGE_FILE_MACHINE_I386", IMAGE_FILE_MACHINE_I386),
        ("IMAGE_FILE_MACHINE_IA64", IMAGE_FILE_MACHINE_IA64),
        ("IMAGE_FILE_MACHINE_M32R", IMAGE_FILE_MACHINE_M32R),
        ("IMAGE_FILE_MACHINE_MIPS16", IMAGE_FILE_MACHINE_MIPS16),
        ("IMAGE_FILE_MACHINE_MIPSFPU", IMAGE_FILE_MACHINE_MIPSFPU),
        ("IMAGE_FILE_MACHINE_MIPSFPU16", IMAGE_FILE_MACHINE_MIPSFPU16),
        ("IMAGE_FILE_MACHINE_POWERPC", IMAGE_FILE_MACHINE_POWERPC),
        ("IMAGE_FILE_MACHINE_POWERPCFP", IMAGE_FILE_MACHINE_POWERPCFP),
        ("IMAGE_FILE_MACHINE_R4000", IMAGE_FILE_MACHINE_R4000),
        ("IMAGE_FILE_MACHINE_RISCV32", IMAGE_FILE_MACHINE_RISCV32),
        ("IMAGE_FILE_MACHINE_RISCV64", IMAGE_FILE_MACHINE_RISCV64),
        ("IMAGE_FILE_MACHINE_RISCV128", IMAGE_FILE_MACHINE_RISCV128),
        ("IMAGE_FILE_MACHINE_SH3", IMAGE_FILE_MACHINE_SH3),
        ("IMAGE_FILE_MACHINE_SH3DSP", IMAGE_FILE_MACHINE_SH3DSP),
        ("IMAGE_FILE_MACHINE_SH4", IMAGE_FILE_MACHINE_SH4),
        ("IMAGE_FILE_MACHINE_SH5", IMAGE_FILE_MACHINE_SH5),
        ("IMAGE_FILE_MACHINE_THUMB", IMAGE_FILE_MACHINE_THUMB),
        ("IMAGE_FILE_MACHINE_WCEMIPSV2", IMAGE_FILE_MACHINE_WCEMIPSV2),
    ])
    machine_named_type = define_named_type(bv, "coff_machine", machine_type)

    subsystem_type = Type.enumeration(arch=bv.arch, width=1, sign=False, members=[
        ("IMAGE_SUBSYSTEM_UNKNOWN", IMAGE_SUBSYSTEM_UNKNOWN),
        ("IMAGE_SUBSYSTEM_NATIVE", IMAGE_SUBSYSTEM_NATIVE),
        ("IMAGE_SUBSYSTEM_WINDOWS_GUI", IMAGE_SUBSYSTEM_WINDOWS_GUI),
        ("IMAGE_SUBSYSTEM_WINDOWS_CUI", IMAGE_SUBSYSTEM_WINDOWS_CUI),
        ("IMAGE_SUBSYSTEM_OS2_CUI", IMAGE_SUBSYSTEM_OS2_CUI),
        ("IMAGE_SUBSYSTEM_POSIX_CUI", IMAGE_SUBSYSTEM_POSIX_CUI),
        ("IMAGE_SUBSYSTEM_NATIVE_WINDOWS", IMAGE_SUBSYSTEM_NATIVE_WINDOWS),
        ("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", IMAGE_SUBSYSTEM_WINDOWS_CE_GUI),
        ("IMAGE_SUBSYSTEM_EFI_APPLICATION", IMAGE_SUBSYSTEM_EFI_APPLICATION),
        ("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER),
        ("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER),
        ("IMAGE_SUBSYSTEM_EFI_ROM", IMAGE_SUBSYSTEM_EFI_ROM),
        ("IMAGE_SUBSYSTEM_XBOX", IMAGE_SUBSYSTEM_XBOX),
        ("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION),
    ])
    subsystem_named_type = define_named_type(bv, "pe_subsystem", subsystem_type)

    data_dir_type = Type.structure([
        (Type.int(4, False), "virtualAddress"),
        (Type.int(4, False), "size"),
    ])
    data_dir_named_type = define_named_type(bv, "EFI_IMAGE_DATA_DIR", data_dir_type)

    te_header_type = Type.structure([
        (Type.array(Type.int(1, True), 2), "signature"),
        (machine_named_type, "machine"),
        (Type.int(1, False), "numberOfSections"),
        (subsystem_named_type, "subsystem"),
        (Type.int(2, False), "strippedSize"),
        (Type.int(4, False), "addressOfEntryPoint"),
        (Type.int(4, False), "baseOfCode"),
        (Type.int(8, False), "imageBase"),
        (Type.array(data_dir_named_type, 2), "dataDirectory"),
    ])
    te_header_named_type = define_named_type(bv, "EFI_TE_IMAGE_HEADER", te_header_type)

    return te_header_named_type

def define_section_header_type(bv: BinaryView) -> NamedTypeReferenceType:
    characteristics_type = Type.enumeration(arch=bv.arch, width=4, sign=False, members=[
        ("IMAGE_SCN_RESERVED_0001", IMAGE_SCN_RESERVED_0001),
        ("IMAGE_SCN_RESERVED_0002", IMAGE_SCN_RESERVED_0002),
        ("IMAGE_SCN_RESERVED_0004", IMAGE_SCN_RESERVED_0004),
        ("IMAGE_SCN_TYPE_NO_PAD", IMAGE_SCN_TYPE_NO_PAD),
        ("IMAGE_SCN_RESERVED_0010", IMAGE_SCN_RESERVED_0010),
        ("IMAGE_SCN_CNT_CODE", IMAGE_SCN_CNT_CODE),
        ("IMAGE_SCN_CNT_INITIALIZED_DATA", IMAGE_SCN_CNT_INITIALIZED_DATA),
        ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", IMAGE_SCN_CNT_UNINITIALIZED_DATA),
        ("IMAGE_SCN_LNK_OTHER", IMAGE_SCN_LNK_OTHER),
        ("IMAGE_SCN_LNK_INFO", IMAGE_SCN_LNK_INFO),
        ("IMAGE_SCN_RESERVED_0400", IMAGE_SCN_RESERVED_0400),
        ("IMAGE_SCN_LNK_REMOVE", IMAGE_SCN_LNK_REMOVE),
        ("IMAGE_SCN_LNK_COMDAT", IMAGE_SCN_LNK_COMDAT),
        ("IMAGE_SCN_GPREL", IMAGE_SCN_GPREL),
        ("IMAGE_SCN_MEM_PURGEABLE", IMAGE_SCN_MEM_PURGEABLE),
        ("IMAGE_SCN_MEM_16BIT", IMAGE_SCN_MEM_16BIT),
        ("IMAGE_SCN_MEM_LOCKED", IMAGE_SCN_MEM_LOCKED),
        ("IMAGE_SCN_MEM_PRELOAD", IMAGE_SCN_MEM_PRELOAD),
        # TODO fix the bug that causes flags to not be displayed when these are added to the enumeration
        # ("IMAGE_SCN_ALIGN_1BYTES", IMAGE_SCN_ALIGN_1BYTES),
        # ("IMAGE_SCN_ALIGN_2BYTES", IMAGE_SCN_ALIGN_2BYTES),
        # ("IMAGE_SCN_ALIGN_4BYTES", IMAGE_SCN_ALIGN_4BYTES),
        # ("IMAGE_SCN_ALIGN_8BYTES", IMAGE_SCN_ALIGN_8BYTES),
        # ("IMAGE_SCN_ALIGN_16BYTES", IMAGE_SCN_ALIGN_16BYTES),
        # ("IMAGE_SCN_ALIGN_32BYTES", IMAGE_SCN_ALIGN_32BYTES),
        # ("IMAGE_SCN_ALIGN_64BYTES", IMAGE_SCN_ALIGN_64BYTES),
        # ("IMAGE_SCN_ALIGN_128BYTES", IMAGE_SCN_ALIGN_128BYTES),
        # ("IMAGE_SCN_ALIGN_256BYTES", IMAGE_SCN_ALIGN_256BYTES),
        # ("IMAGE_SCN_ALIGN_512BYTES", IMAGE_SCN_ALIGN_512BYTES),
        # ("IMAGE_SCN_ALIGN_1024BYTES", IMAGE_SCN_ALIGN_1024BYTES),
        # ("IMAGE_SCN_ALIGN_2048BYTES", IMAGE_SCN_ALIGN_2048BYTES),
        # ("IMAGE_SCN_ALIGN_4096BYTES", IMAGE_SCN_ALIGN_4096BYTES),
        # ("IMAGE_SCN_ALIGN_8192BYTES", IMAGE_SCN_ALIGN_8192BYTES),
        ("IMAGE_SCN_LNK_NRELOC_OVFL", IMAGE_SCN_LNK_NRELOC_OVFL),
        ("IMAGE_SCN_MEM_DISCARDABLE", IMAGE_SCN_MEM_DISCARDABLE),
        ("IMAGE_SCN_MEM_NOT_CACHED", IMAGE_SCN_MEM_NOT_CACHED),
        ("IMAGE_SCN_MEM_NOT_PAGED", IMAGE_SCN_MEM_NOT_PAGED),
        ("IMAGE_SCN_MEM_SHARED", IMAGE_SCN_MEM_SHARED),
        ("IMAGE_SCN_MEM_EXECUTE", IMAGE_SCN_MEM_EXECUTE),
        ("IMAGE_SCN_MEM_READ", IMAGE_SCN_MEM_READ),
        ("IMAGE_SCN_MEM_WRITE", IMAGE_SCN_MEM_WRITE),
    ])

    characteristics_named_type = define_named_type(bv, "pe_section_flags", characteristics_type)

    section_header_type = Type.structure([
        (Type.array(Type.int(1, True), 8), "name"),
        (Type.int(4, False), "virtualSize"),
        (Type.int(4, False), "virtualAddress"),
        (Type.int(4, False), "sizeOfRawData"),
        (Type.int(4, False), "pointerToRawData"),
        (Type.int(4, False), "pointerToRelocations"),
        (Type.int(4, False), "pointerToLineNumbers"),
        (Type.int(2, False), "numberOfRelocations"),
        (Type.int(2, False), "numberOfLineNumbers"),
        (characteristics_named_type, "characteristics"),
    ])

    section_header_named_type = define_named_type(bv, "Section_Header", section_header_type)

    return section_header_named_type
