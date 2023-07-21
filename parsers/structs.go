package parsers

type PMemInfo struct {
	BaseAddress       uint64
	AllocationProtect uint64
	Protect           string
	State             uint32
	Type              uint32
	RegionSize        uint64
}

type PMemRange struct {
	AddrMemoryRange uint64
	LenData         uint32
	OfsData         uint32
	Data            []byte
}

type PMemRange64 struct {
	StartOfMemoryRange uint64
	DataSize           uint64
	Data               []byte
}

type PThread struct {
	ThreadId        uint32
	AddrMemoryRange uint64
	SuspendCount    uint32
	Priority        uint32
	Teb             uint64
	ThreadContext   uint32
}

type PModule struct {
	BaseOfImage   uint64
	SizeOfImage   uint32
	CheckSum      uint32
	TimeDateStamp uint32
	ModuleNameRva uint32
	ModuleName    string
}

type PHandleDescriptor struct {
	Handle        uint64
	TypeNameRva   uint32
	ObjectNameRva uint32
	Attributes    uint32
	GrantedAccess uint32
	CountHandle   uint32
	CountPointer  uint32
	TypeName      string
	ObjectName    string
	ObjectInfoRva uint32
}
