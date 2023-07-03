from binaryninja import BinaryView, Platform, SegmentFlag, SectionSemantics, Type, Symbol, SymbolType
from binaryninja import log

from .teheaders import define_te_header_type, define_section_header_type

import struct

TERSE_IMAGE_HEADER_SIZE = 0x28
SECTION_HEADER_SIZE = 0x28

class TerseExecutableView(BinaryView):
    """
    Class representing a binary view for UEFI Terse Executables (TE)
    """

    name = 'TE'
    long_name = 'Terse Executable'

    def __init__(self, data: BinaryView):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        hdr = data.read(0, TERSE_IMAGE_HEADER_SIZE)

        if len(hdr) < TERSE_IMAGE_HEADER_SIZE:
            return False

        if hdr[0x00:0x02] != b'VZ':
            return False

        return True

    def _set_platform(self, machine: int):
        """
        Set the platform/architecture for the view. This field is inherited from the PE format and so takes on the same values. We match on the subset of values that correspond to platforms that Binja directly supports.

        :param machine: Machine type from TE header
        """
        platforms = {
            0x1c0:  Platform['efi-armv7'],
            0x1c4:  Platform['efi-thumb2'],
            0x14c:  Platform['efi-x86'],
            0x8664: Platform['efi-x86_64'],
            0xaa64: Platform['efi-aarch64'],
        }

        self.platform = platforms[machine]
        self.arch = self.platform.arch

    def _create_segments(self, image_base: int, header_offset: int, code_offset: int, num_sections: int):
        """
        Create segments. One read-only segment for the headers and a RWX segment for everything else.
        """
        header_size = TERSE_IMAGE_HEADER_SIZE + num_sections * SECTION_HEADER_SIZE
        self.add_auto_segment(image_base + header_offset, header_size, 0, header_size, SegmentFlag.SegmentReadable)
        code_size = self.raw.length - header_size
        self.add_auto_segment(
            image_base + code_offset, code_size, code_offset - header_offset, code_size,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable
        )

    def _create_sections(self, image_base: int, num_sections: int):
        """
        Section headers are formatted the same as in a PE file.
        """
        for i in range(num_sections):
            base = TERSE_IMAGE_HEADER_SIZE + i*SECTION_HEADER_SIZE
            section = self.raw[base:base+SECTION_HEADER_SIZE]
            name = section[0x00:0x08].decode()
            virtual_size = struct.unpack('<I', section[0x8:0xc])[0]
            virtual_addr = struct.unpack('<I', section[0xc:0x10])[0]

            characteristics = struct.unpack('<I', section[0x24:0x28])[0]
            flags = 0
            if characteristics & 0x80000000:
                flags |= SegmentFlag.SegmentWritable;
            if characteristics & 0x40000000:
                flags |= SegmentFlag.SegmentReadable;
            if characteristics & 0x20000000:
                flags |= SegmentFlag.SegmentExecutable;
            if characteristics & 0x00000080:
                flags |= SegmentFlag.SegmentContainsData;
            if characteristics & 0x00000040:
                flags |= SegmentFlag.SegmentContainsData;
            if characteristics & 0x00000020:
                flags |= SegmentFlag.SegmentContainsCode;

            pFlags = flags & 0x7
            semantics = SectionSemantics.DefaultSectionSemantics
            if pFlags == SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable:
                semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
            elif pFlags == SegmentFlag.SegmentReadable:
                semantics = SectionSemantics.ReadOnlyDataSectionSemantics
            elif pFlags == SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable:
                semantics = SectionSemantics.ReadWriteDataSectionSemantics

            self.add_auto_section(name, image_base + virtual_addr, virtual_size, semantics)

    def _apply_header_types(self, image_base: int, header_offset: int, num_sections: int):
        te_header_type = define_te_header_type(self)
        te_header_addr = image_base + header_offset
        self.define_data_var(te_header_addr, te_header_type)
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, te_header_addr, '__te_header'))

        section_header_type = define_section_header_type(self)
        section_headers_addr = image_base + header_offset + TERSE_IMAGE_HEADER_SIZE
        self.define_data_var(section_headers_addr, Type.array(section_header_type, num_sections))
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, section_headers_addr, '__section_headers'))

    def init(self) -> bool:
        hdr = self.raw.read(0, 0x28)

        machine = struct.unpack('<H', hdr[0x02:0x04])[0]
        self._set_platform(machine)

        num_sections = hdr[4]
        subsystem = hdr[5]
        stripped_size = struct.unpack('<H', hdr[0x06:0x08])[0]
        entry_addr = struct.unpack('<I', hdr[0x08:0x0c])[0]
        code_offset = struct.unpack('<I', hdr[0x0c:0x10])[0]
        image_base = struct.unpack('<Q', hdr[0x10:0x18])[0]

        headers_offset = stripped_size - TERSE_IMAGE_HEADER_SIZE # Don't question it...

        print(f'image base: {image_base:x}')
        print(f'header offset: {headers_offset:x}')
        print(f'header addr: {image_base + headers_offset:x}')
        print(f'code offset: {code_offset:x}')
        print(f'code addr: {image_base + code_offset:x}')

        self._create_segments(image_base, headers_offset, code_offset, num_sections)
        self._create_sections(image_base, num_sections)
        self._apply_header_types(image_base, headers_offset, num_sections)

        self.entry_addr = image_base + entry_addr
        self.add_entry_point(self.entry_addr)
        return True

    def perform_is_executable(self) -> int:
        return True

    def perform_get_entry_point(self) -> int:
        return self.entry_addr

    def perform_get_address_size(self) -> int:
        assert self.platform
        return self.platform.arch.address_size
