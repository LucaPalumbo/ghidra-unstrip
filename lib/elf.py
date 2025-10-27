# -*- coding: utf-8 -*-

# originally from: https://github.com/cesena/ghidra2dwarf

import struct

class ElfBase(object):
	def __init__(self, file_offset, map, values, **kwargs):
		self.__dict__['map'] = map
		self.file_offset = file_offset
		for n, v in zip(map, values):
			if isinstance(n, tuple):
				n, f = n
				v = f(v)
			setattr(self, n, v)

	@property
	def values(self):
		vv = (getattr(self, n[0] if isinstance(n, tuple) else n) for n in self.map)
		return [v.code if isinstance(v, DumbEnumValue) else v for v in vv]

	def __setattr__(self, name, value):
		if not hasattr(self, 'repr_pos'):
			object.__setattr__(self, 'repr_pos', {})
		if name not in self.repr_pos:
			self.repr_pos[name] = len(self.repr_pos)
		return object.__setattr__(self, name, value)

	def __repr__(self):
		args = ', '.join('%s=%r' % (n, getattr(self, n)) for n, _ in sorted(self.repr_pos.items(), key=lambda x: x[1]))
		return '%s(%s)' % (self.__class__.__name__, args)

class ElfIdent(ElfBase):
	def __init__(self, values, file_offset):
		return ElfBase.__init__(self, file_offset, [
			'magic',
			('elf_class', ElfClass.__getitem__),
			('elf_data', ElfData.__getitem__),
			'file_version',
			'osabi',
			'abi_version',
		], values)

class ElfHeader(ElfBase):
	def __init__(self, values, file_offset):
		return ElfBase.__init__(self, file_offset, [
			('type', ET.__getitem__),
			('machine', EM.__getitem__),
			'version',
			'entry',
			'phoff',
			'shoff',
			'flags',
			'ehsize',
			'phentsize',
			'phnum',
			'shentsize',
			'shnum',
			'shstrndx',
		], values)

class ElfSectionHeader(ElfBase):
	def __init__(self, values, file_offset):
		self.name = ''
		return ElfBase.__init__(self, file_offset, [
			'name_offset',
			('type', SHT.__getitem__),
			'flags',
			'addr',
			'offset',
			'section_size',
			'link',
			'info',
			'addralign',
			'entsize',
		], values)


struct_coders = {
	'ElfIdent': struct.Struct('=4sBBBBBxxxxxxx'),
	'ElfHeader': {
		'32le': struct.Struct('<HHIIIIIHHHHHH'),
		'32be': struct.Struct('>HHIIIIIHHHHHH'),
		'64le': struct.Struct('<HHIQQQIHHHHHH'),
		'64be': struct.Struct('>HHIQQQIHHHHHH'),
	},
	'ElfSectionHeader': {
		'32le': struct.Struct('<IIIIIIIIII'),
		'32be': struct.Struct('>IIIIIIIIII'),
		'64le': struct.Struct('<IIQQQQIIQQ'),
		'64be': struct.Struct('>IIQQQQIIQQ'),
	}
}

class Elf:
	def __init__(self, bytes):
		self.bytes = bytearray(bytes)
		self.extract_ident()
		bits = '64' if self.ident.elf_class == ElfClass.ELFCLASS64 else '32'
		#bits = '64' if ElfClass[self.ident.elf_class] == ElfClass.ELFCLASS64 else '32'
		endianness = 'le' if self.ident.elf_data == ElfData.ELFDATA2LSB else 'be'
		#endianness = 'le' if ElfData[self.ident.elf_data] == ElfData.ELFDATA2LSB else 'be'
		self.type = bits + endianness
		self.new_sections = []

	def _get_struct(self, cls):
		s = struct_coders[cls.__name__]
		return s[self.type] if isinstance(s, dict) else s

	def _dump_struct(self, cls, off):
		s = self._get_struct(cls)
		# unpack_from doesn't work with jython
		# return cls(s.unpack_from(self.bytes, off), file_offset=off)
		bb = self.bytes[off:off+s.size]
		# Python 3 fix: don't convert bytes to str
		return cls(s.unpack(bytes(bb)), file_offset=off)

	def _export_struct(self, val, off):
		s = self._get_struct(val.__class__)
		# unpack_into doesn't work with jython
		# s.pack_into(self.bytes, off, *val.values)
		self.bytes[off:off+s.size] = s.pack(*val.values)

	def extract_ident(self):
		if hasattr(self, 'ident'):
			return self.ident
		self.ident = self._dump_struct(ElfIdent, 0)
		self.header_off = self._get_struct(ElfIdent).size
		return self.ident

	def extract_header(self):
		if hasattr(self, 'header'):
			return self.header
		self.header = self._dump_struct(ElfHeader, self.header_off)
		return self.header

	def extract_section_headers(self):
		if hasattr(self, 'section_headers'):
			return self.section_headers

		self.section_headers = []
		h = self.extract_header()
		for i in range(h.shnum):
			self.section_headers.append(self._dump_struct(ElfSectionHeader, h.shoff + i * h.shentsize))
		self.section_names = self.extract_section(self.section_headers[h.shstrndx])
		for s in self.section_headers:
			# Python 3 fix: handle bytes properly
			null_pos = self.section_names.find(b'\x00', s.name_offset)
			if null_pos == -1:
				null_pos = len(self.section_names)
			s.name = self.section_names[s.name_offset:null_pos].decode('utf-8', errors='replace')
		return self.section_headers

	def extract_section(self, section_header):
		return self.bytes[section_header.offset:section_header.offset+section_header.section_size]

	def encode_section_header(self, section_header):
		return self._get_struct(ElfSectionHeader).pack(*section_header.values)

	def add_section(self, name, body):
		self.new_sections.append((name, body))

	def generate_updated_elf(self):
		section_headers = self.extract_section_headers()
		added_sections = False
		for name, body in self.new_sections:
			try:
				s = next(s for s in section_headers if s.name == name)
			except:
				added_sections = True
				name_off = len(self.section_names)
				# Python 3 fix: encode string to bytes
				self.section_names += name.encode('utf-8') + b'\x00'
				s = ElfSectionHeader([name_off, 1, 0, 0, -1, -1, 0, 0, 1, 0], file_offset=-1)
				s.name = name
				section_headers.append(s)
			s.offset = len(self.bytes)
			s.section_size = len(body)
			# Python 3 fix: ensure body is bytes
			self.bytes += bytes(body)

		h = self.header
		if added_sections:
			shstr = section_headers[h.shstrndx]
			shstr.section_size = len(self.section_names)
			shstr.offset = len(self.bytes)
			self.bytes += self.section_names
			h.shoff = len(self.bytes)
			h.shnum = len(section_headers)
			# Python 3 fix: use bytes instead of string
			self.bytes += b'\x00' * h.shentsize * h.shnum

		self._export_struct(h, self.header_off)
		for i, s in enumerate(section_headers):
			s.file_offset = h.shoff + i * h.shentsize
			self._export_struct(s, s.file_offset)

		return self.bytes

def add_sections_to_elf(from_file, to_file, sections):
	with open(from_file, 'rb') as f:
		bb = f.read()
	e = Elf(bb)

	for name, s in sections:
		e.add_section(name, s)
	out = e.generate_updated_elf()
	with open(to_file, 'wb') as f:
		f.write(out)
