meta:
  id: windows_minidump
  title: Windows MiniDump
  file-extension:
    - dmp
    - mdmp
  license: MIT
  endian: le
doc: |
  Windows MiniDump (MDMP) file provides a concise way to store process
  core dumps, which is useful for debugging. Given its small size,
  modularity, some cross-platform features and native support in some
  debuggers, it is particularly useful for crash reporting, and is
  used for that purpose in Windows and Google Chrome projects.

  The file itself is a container, which contains a number of typed
  "streams", which contain some data according to its type attribute.
doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_header
seq:
  - id: magic1
    -orig-id: Signature
    contents: MDMP
  - id: magic2
    -orig-id: Version
    contents: [0x93, 0xa7]
  - id: version
    -orig-id: Version
    type: u2
  - id: num_streams
    -orig-id: NumberOfStreams
    type: u4
  - id: ofs_streams
    -orig-id: StreamDirectoryRva
    type: u4
  - id: checksum
    -orig-id: CheckSum
    type: u4
  - id: timestamp
    -orig-id: TimeDateStamp
    type: u4
  - id: flags
    type: u8
instances:
  streams:
    pos: ofs_streams
    type: dir
    repeat: expr
    repeat-expr: num_streams
types:
  dir:
    -orig-id: MINIDUMP_DIRECTORY
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_directory
    seq:
      - id: stream_type
        -orig-id: StreamType
        type: u4
        enum: stream_types
      - id: len_data
        -orig-id: DataSize
        type: u4
        doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_location_descriptor
      - id: ofs_data
        type: u4
        -orig-id: Rva
    instances:
      data:
        pos: ofs_data
        size: len_data
        type:
          switch-on: stream_type
          cases:
            'stream_types::system_info': system_info
            'stream_types::misc_info': misc_info
            'stream_types::thread_list': thread_list
            'stream_types::memory_list': memory_list
            'stream_types::memory_64_list': memory_64_list
            'stream_types::exception': exception_stream
            'stream_types::memory_info_list': memory_info_list
            'stream_types::module_list': module_list
            'stream_types::unloaded_module_list': unloaded_module_list
            'stream_types::handle_data': handle_data
  system_info:
    doc: |
      "System info" stream provides basic information about the
      hardware and operating system which produces this dump.
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_system_info
    seq:
      - id: cpu_arch
        -orig-id: ProcessorArchitecture
        type: u2
        enum: cpu_archs
      - id: cpu_level
        -orig-id: ProcessorLevel
        type: u2
      - id: cpu_revision
        -orig-id: ProcessorRevision
        type: u2
      - id: num_cpus
        -orig-id: NumberOfProcessors
        type: u1
      - id: os_type
        -orig-id: ProductType
        type: u1
      - id: os_ver_major
        -orig-id: MajorVersion
        type: u4
      - id: os_ver_minor
        -orig-id: MinorVersion
        type: u4
      - id: os_build
        -orig-id: BuildNumber
        type: u4
      - id: os_platform
        -orig-id: PlatformId
        type: u4
      - id: ofs_service_pack
        -orig-id: CSDVersionRva
        type: u4
      - id: os_suite_mask
        type: u2
      - id: reserved2
        type: u2
      # TODO: the rest of CPU information
    instances:
      service_pack:
        io: _root._io
        pos: ofs_service_pack
        type: minidump_string
        if: ofs_service_pack > 0
    enums:
      cpu_archs:
        0: intel
        5: arm
        6: ia64
        9: amd64
        0xffff: unknown
  misc_info:
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_misc_info
    # https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_misc_info_2
    seq:
      - id: len_info
        -orig-id: SizeOfInfo
        type: u4
      - id: flags1
        -orig-id: Flags1
        type: u4
      - id: process_id
        -orig-id: ProcessId
        type: u4
      - id: process_create_time
        -orig-id: ProcessCreateTime
        type: u4
      - id: process_user_time
        -orig-id: ProcessUserTime
        type: u4
      - id: process_kernel_time
        -orig-id: ProcessKernelTime
        type: u4
      - id: cpu_max_mhz
        -orig-id: ProcessorMaxMhz
        type: u4
      - id: cpu_cur_mhz
        -orig-id: ProcessorCurrentMhz
        type: u4
      - id: cpu_limit_mhz
        -orig-id: ProcessorMhzLimit
        type: u4
      - id: cpu_max_idle_state
        -orig-id: ProcessorMaxIdleState
        type: u4
      - id: cpu_cur_idle_state
        -orig-id: ProcessorCurrentIdleState
        type: u4
  unloaded_module_list:
    -orig-id: MINIDUMP_UNLOADED_MODULE_LIST
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_unloaded_module_list
    seq:
      - id: len_of_header
        -orig-id: SizeOfHeader
        type: u4
      - id: len_of_entry
        -orig-id: SizeOfEntry
        type: u4
      - id: num_unloaded_modules
        -orig-id: NumberOfEntries
        type: u4
      - id: unloaded_modules
        type: unloaded_module
        repeat: expr
        repeat-expr: num_unloaded_modules
  unloaded_module:
    -orig-id: MINIDUMP_UNLOADED_MODULE
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_unloaded_module
    seq:
      - id: base_of_image
        -orig-id: BaseOfImage
        type: u8
      - id: size_of_image
        type: u4
      - id: check_sum
        -orig-id: CheckSum
        type: u4
      - id: time_date_stamp
        -orig-id: TimeDateStamp
        type: u4
      - id: module_name_rva
        -orig-id: ModuleNameRva
        type: u4
    instances:
      len_unloaded_module_name:
        io: _root._io
        pos: module_name_rva
        type: u4
      unloaded_module_name:
        pos: module_name_rva + 4
        type: str
        encoding: UTF-16LE
        size: len_unloaded_module_name
        io: _root._io
  module_list:
    -orig-id: MINIDUMP_MODULE_LIST
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_module
    seq:
      - id: num_modules
        -orig-id: NumberOfModules
        type: u4
      - id: modules
        -orig-id: Modules
        type: module
        repeat: expr
        repeat-expr: num_modules
  module:
    -orig-id: MINIDUMP_MODULE
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_module
    seq:
      - id: base_of_image
        -orig-id: BaseOfImage
        type: u8
      - id: size_of_image
        type: u4
      - id: check_sum
        -orig-id: CheckSum
        type: u4
      - id: time_date_stamp
        -orig-id: TimeDateStamp
        type: u4
      - id: module_name_rva
        -orig-id: ModuleNameRva
        type: u4
      - id: version_info
        -orid-id: VersionInfo
        type: vs_filedfileinfo
      - id: cv_record
        -orig-id: CvRecord
        type: location_descriptor
      - id: misc_record
        -orig-id: MiscRecord
        type: location_descriptor
      - id: reserved0
        -orig-id: Reserved0
        type: u8
      - id: reserved1
        -orig-id: Reserved1
        type: u8
    instances:
      len_module_name:
        io: _root._io
        pos: module_name_rva
        type: u4
      module_name:
        pos: module_name_rva + 4
        type: str
        encoding: UTF-16LE
        size: len_module_name
        io: _root._io
  vs_filedfileinfo:
    -orig-id: VS_FIXEDFILEINFO
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
    seq:
      - id: signature
        -orig-id: dwSignature
        type: u4
      - id: struc_version
        -orig-id: dwStrucVersion
        type: u4
      - id: file_version_ms
        -orig-id: dwFileVersionMS
        type: u4
      - id: file_version_ls
        -orig-id: dwFileVersionLS
        type: u4
      - id: product_version_ms
        -orig-id: dwProductVersionMS
        type: u4
      - id: product_version_ls
        -orig-id: dwProductVersionLS
        type: u4
      - id: file_flags_mask
        -orig-id: dwFileFlagsMask
        type: u4
      - id: file_flags
        -orig-id: dwFileFlags
        type: u4
      - id: file_os
        -orig-id: dwFileOS
        type: u4
      - id: file_type
        -orig-id: dwFileType
        type: u4
      - id: file_subtype
        -orig-id: dwFileSubtype
        type: u4
      - id: file_date_ms
        -orig-id: dwFileDateMS
        type: u4
      - id: file_date_ls
        -orig-id: dwFileDateLS
        type: u4
  thread_list:
    -orig-id: MINIDUMP_THREAD_LIST
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_thread_list
    seq:
      - id: num_threads
        -orig-id: NumberOfThreads
        type: u4
      - id: threads
        -orig-id: Threads
        type: thread
        repeat: expr
        repeat-expr: num_threads
  thread:
    -orig-id: MINIDUMP_THREAD
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_thread
    seq:
      - id: thread_id
        -orig-id: ThreadId
        type: u4
      - id: suspend_count
        -orig-id: SuspendCount
        type: u4
      - id: priority_class
        -orig-id: PriorityClass
        type: u4
      - id: priority
        -orig-id: Priority
        type: u4
      - id: teb
        -orig-id: Teb
        type: u8
        doc: Thread Environment Block
      - id: stack
        -orig-id: Stack
        type: memory_descriptor
      - id: thread_context
        -orig-id: ThreadContext
        type: location_descriptor
  memory_list:
    -orig-id: MINIDUMP_MEMORY_LIST
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory64_list
    seq:
      - id: num_mem_ranges
        type: u4
      - id: mem_ranges
        type: memory_descriptor
        repeat: expr
        repeat-expr: num_mem_ranges
  memory_64_list:
    -orig-id: MINIDUMP_MEMORY_LIST64
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory64_list
    seq:
      - id: num_mem_ranges
        type: u8
      - id: base_rva
        type: u8
      - id: mem_ranges
        type: memory_descriptor64
        repeat: expr
        repeat-expr: num_mem_ranges
  memory_info_list:
    -orig-id: MINIDUMP_MEMORY_INFO_LIST 
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_info_list?redirectedfrom=MSDN
    seq:
      - id: size_of_header
        type: u4
      - id: size_of_entry
        type: u4
      - id: num_entries
        type: u8
      - id: entries
        type: memory_info
        repeat: expr
        repeat-expr: num_entries
  memory_info:
    -orig-id: MINIDUMP_MEMORY_INFO
    doc-ref: https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_info
    seq:
      - id: base_address
        -orig-id: BaseAddress
        type: u8
      - id: allocation_base
        -orig-id: AllocationBase
        type: u8
      - id: allocation_protect
        -orig-id: AllocationProtect
        type: u4
      - id: alignment1
        -orig-id: alignment1
        type: u4
      - id: region_size
        -orig-id: RegionSize
        type: u8
      - id: state
        -orig-id: State
        type: u4
      - id: protect
        -orig-id: Protect
        type: u4
      - id: type
        -orig-id: Type
        type: u4
      - id: alignment2
        -orig-id: alignment2
        type: u4
  exception_stream:
    -orig-id: MINIDUMP_EXCEPTION_STREAM
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_exception_stream
    seq:
      - id: thread_id
        -orig-id: ThreadId
        type: u4
      - id: reserved
        -orig-id: __alignment
        type: u4
      - id: exception_rec
        -orig-id: ExceptionRecord
        type: exception_record
      - id: thread_context
        -orig-id: ThreadContext
        type: location_descriptor
  exception_record:
    -orig-id: MINIDUMP_EXCEPTION
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_exception
    seq:
      - id: code
        -orig-id: ExceptionCode
        type: u4
      - id: flags
        -orig-id: ExceptionFlags
        type: u4
      - id: inner_exception
        -orig-id: ExceptionRecord
        type: u8
      - id: addr
        -orig-id: ExceptionAddress
        type: u8
        doc: Memory address where exception has occurred
      - id: num_params
        -orig-id: NumberParameters
        type: u4
      - id: reserved
        -orig-id: __unusedAlignment
        type: u4
      - id: params
        -orig-id: ExceptionInformation
        type: u8
        repeat: expr
        repeat-expr: 15
        doc: |
          Additional parameters passed along with exception raise
          function (for WinAPI, that is `RaiseException`). Meaning is
          exception-specific. Given that this type is originally
          defined by a C structure, it is described there as array of
          fixed number of elements (`EXCEPTION_MAXIMUM_PARAMETERS` =
          15), but in reality only first `num_params` would be used.
  handle_data:
    -orig-id: MINIDUMP_HANDLE_DATA_STREAM
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_handle_data_stream
    seq:
      - id: len_of_header
        -orig-id: SizeOfHeader
        type: u4
      - id: len_handles
        -orig-id: SizeOfDescriptor
        type: u4
      - id: num_handles
        -orig-id: NumberOfDescriptors
        type: u4
      - id: reserved
        -orig-id: Reserved
        type: u4
      - id: handles
        type: handle_descriptor
        repeat: expr
        repeat-expr: num_handles
        size: len_handles
  handle_descriptor:
    -orig-id: MINIDUMP_HANDLE_DESCRIPTOR
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_handle_descriptor
    seq:
      - id: handle
        -orig-id: Handle
        type: u8
      - id: type_name_rva
        -orig-id: TypeNameRva
        type: u4
      - id: object_name_rva
        -orig-id: ObjectNameRva
        type: u4
      - id: attributes
        -orig-id: Attributes
        type: u4
      - id: granted_access
        -orig-id: GrantedAccess
        type: u4
      - id: count_handle
        -orig-id: HandleCount
        type: u4
      - id: count_pointer
        -orig-id: PointerCount
        type: u4
      - id: object_info_rva
        -orig-id: ObjectInfoRva
        type: u4
    instances:
      type_name_descriptor:
        io: _root._io
        pos: type_name_rva
        type: minidump_string
        if: type_name_rva > 0
      object_name_descriptor:
        io: _root._io
        pos: object_name_rva
        type: minidump_string
        if: object_name_rva > 0
  memory_descriptor:
    -orig-id: MINIDUMP_MEMORY_DESCRIPTOR
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_descriptor
    seq:
      - id: addr_memory_range
        -orig-id: StartOfMemoryRange
        type: u8
      - id: memory
        type: location_descriptor
  memory_descriptor64:
    -orig-id: _MINIDUMP_MEMORY_DESCRIPTOR64
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_location_descriptor64
    seq:
      - id: start_of_memory_range
        -orig-id: StartOfMemoryRange
        type: u8
      - id: len_data
        type: u8
    instances:
      data:
        io: _root._io
        pos: _parent.base_rva
        size: len_data
  location_descriptor:
    -orig-id: MINIDUMP_LOCATION_DESCRIPTOR
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_location_descriptor
    seq:
      - id: len_data
        -orig-id: DataSize
        type: u4
      - id: ofs_data
        -orig-id: Rva
        type: u4
    instances:
      data:
        io: _root._io
        pos: ofs_data
        size: len_data
  location_descriptor64:
    -orig-id: MINIDUMP_LOCATION_DESCRIPTOR64 
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_location_descriptor64
    seq:
      - id: len_data
        -orig-id: DataSize
        type: u8
      - id: ofs_data
        -orig-id: Rva
        type: u8
    instances:
      data:
        io: _root._io
        pos: ofs_data
        size: len_data
  minidump_string:
    doc: |
      Specific string serialization scheme used in MiniDump format is
      actually a simple 32-bit length-prefixed UTF-16 string.
    doc-ref: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_string
    seq:
      - id: len_str
        -orig-id: Length
        type: u4
      - id: str
        -orig-id: Buffer
        size: len_str
        type: str
        encoding: UTF-16LE
enums:
  stream_types:
    # https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_stream_type
    0: unused
    1: reserved_0
    2: reserved_1
    3: thread_list
    4: module_list
    5: memory_list
    6: exception
    7: system_info
    8: thread_ex_list
    9: memory_64_list
    10: comment_a
    11: comment_w
    12: handle_data
    13: function_table
    14: unloaded_module_list
    15: misc_info
    16: memory_info_list
    17: thread_info_list
    18: handle_operation_list
    19: token
    20: java_script_data
    21: system_memory_info
    22: process_vm_counters
    23: ipt_trace
    24: thread_names
    0x8000: ce_null
    0x8001: ce_system_info
    0x8002: ce_exception
    0x8003: ce_module_list
    0x8004: ce_process_list
    0x8005: ce_thread_list
    0x8006: ce_thread_context_list
    0x8007: ce_thread_call_stack_list
    0x8008: ce_memory_virtual_list
    0x8009: ce_memory_physical_list
    0x800A: ce_bucket_parameters
    0x800B: ce_process_module_map
    0x800C: ce_diagnosis_list
    # Breakpad extensions; see Breakpad's src/google_breakpad/common/minidump_format.h
    0x47670001: md_raw_breakpad_info
    0x47670002: md_raw_assertion_info
    0x47670003: md_linux_cpu_info      # /proc/cpuinfo
    0x47670004: md_linux_proc_status   # /proc/$x/status
    0x47670005: md_linux_lsb_release   # /etc/lsb-release
    0x47670006: md_linux_cmd_line      # /proc/$x/cmdline
    0x47670007: md_linux_environ       # /proc/$x/environ
    0x47670008: md_linux_auxv          # /proc/$x/auxv
    0x47670009: md_linux_maps          # /proc/$x/maps
    0x4767000a: md_linux_dso_debug
    # Crashpad extension; See Crashpad's minidump/minidump_extensions.h
    0x43500001: md_crashpad_info_stream