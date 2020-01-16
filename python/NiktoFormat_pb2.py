# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: NiktoFormat.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='NiktoFormat.proto',
  package='NiktoFormat',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=b'\n\x11NiktoFormat.proto\x12\x0bNiktoFormat\"\xc0\x02\n\x04Scan\x12%\n\x05hosts\x18\x01 \x03(\x0b\x32\x16.NiktoFormat.Scan.Host\x1a\x90\x02\n\x04Host\x12\x0c\n\x04host\x18\x01 \x01(\t\x12\n\n\x02ip\x18\x02 \x01(\t\x12\x0c\n\x04port\x18\x03 \x01(\r\x12\x11\n\tstarttime\x18\x04 \x01(\t\x12\x0e\n\x06\x63hecks\x18\x05 \x01(\r\x12*\n\x05vulns\x18\x06 \x03(\x0b\x32\x1b.NiktoFormat.Scan.Host.Vuln\x1aj\n\x04Vuln\x12\n\n\x02id\x18\x01 \x01(\r\x12-\n\x06method\x18\x02 \x01(\x0e\x32\x1d.NiktoFormat.Scan.Host.Method\x12\x0c\n\x04\x64\x65sc\x18\x03 \x01(\t\x12\x0b\n\x03uri\x18\x04 \x01(\t\x12\x0c\n\x04link\x18\x05 \x01(\t\"%\n\x06Method\x12\x07\n\x03GET\x10\x00\x12\x08\n\x04POST\x10\x01\x12\x08\n\x04HEAD\x10\x02\x62\x06proto3'
)



_SCAN_HOST_METHOD = _descriptor.EnumDescriptor(
  name='Method',
  full_name='NiktoFormat.Scan.Host.Method',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='GET', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='POST', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='HEAD', index=2, number=2,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=318,
  serialized_end=355,
)
_sym_db.RegisterEnumDescriptor(_SCAN_HOST_METHOD)


_SCAN_HOST_VULN = _descriptor.Descriptor(
  name='Vuln',
  full_name='NiktoFormat.Scan.Host.Vuln',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='NiktoFormat.Scan.Host.Vuln.id', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='method', full_name='NiktoFormat.Scan.Host.Vuln.method', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='desc', full_name='NiktoFormat.Scan.Host.Vuln.desc', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='uri', full_name='NiktoFormat.Scan.Host.Vuln.uri', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='link', full_name='NiktoFormat.Scan.Host.Vuln.link', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=210,
  serialized_end=316,
)

_SCAN_HOST = _descriptor.Descriptor(
  name='Host',
  full_name='NiktoFormat.Scan.Host',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='host', full_name='NiktoFormat.Scan.Host.host', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ip', full_name='NiktoFormat.Scan.Host.ip', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='NiktoFormat.Scan.Host.port', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='starttime', full_name='NiktoFormat.Scan.Host.starttime', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='checks', full_name='NiktoFormat.Scan.Host.checks', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='vulns', full_name='NiktoFormat.Scan.Host.vulns', index=5,
      number=6, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[_SCAN_HOST_VULN, ],
  enum_types=[
    _SCAN_HOST_METHOD,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=83,
  serialized_end=355,
)

_SCAN = _descriptor.Descriptor(
  name='Scan',
  full_name='NiktoFormat.Scan',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='hosts', full_name='NiktoFormat.Scan.hosts', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[_SCAN_HOST, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=35,
  serialized_end=355,
)

_SCAN_HOST_VULN.fields_by_name['method'].enum_type = _SCAN_HOST_METHOD
_SCAN_HOST_VULN.containing_type = _SCAN_HOST
_SCAN_HOST.fields_by_name['vulns'].message_type = _SCAN_HOST_VULN
_SCAN_HOST.containing_type = _SCAN
_SCAN_HOST_METHOD.containing_type = _SCAN_HOST
_SCAN.fields_by_name['hosts'].message_type = _SCAN_HOST
DESCRIPTOR.message_types_by_name['Scan'] = _SCAN
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Scan = _reflection.GeneratedProtocolMessageType('Scan', (_message.Message,), {

  'Host' : _reflection.GeneratedProtocolMessageType('Host', (_message.Message,), {

    'Vuln' : _reflection.GeneratedProtocolMessageType('Vuln', (_message.Message,), {
      'DESCRIPTOR' : _SCAN_HOST_VULN,
      '__module__' : 'NiktoFormat_pb2'
      # @@protoc_insertion_point(class_scope:NiktoFormat.Scan.Host.Vuln)
      })
    ,
    'DESCRIPTOR' : _SCAN_HOST,
    '__module__' : 'NiktoFormat_pb2'
    # @@protoc_insertion_point(class_scope:NiktoFormat.Scan.Host)
    })
  ,
  'DESCRIPTOR' : _SCAN,
  '__module__' : 'NiktoFormat_pb2'
  # @@protoc_insertion_point(class_scope:NiktoFormat.Scan)
  })
_sym_db.RegisterMessage(Scan)
_sym_db.RegisterMessage(Scan.Host)
_sym_db.RegisterMessage(Scan.Host.Vuln)


# @@protoc_insertion_point(module_scope)