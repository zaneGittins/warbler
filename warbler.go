package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/jedib0t/go-pretty/v6/table"
	kaitai "github.com/kaitai-io/kaitai_struct_go_runtime/kaitai"
	analysis "github.com/zaneGittins/minidump/analysis"
	misc "github.com/zaneGittins/minidump/misc"
	parsers "github.com/zaneGittins/minidump/parsers"
)

const (
	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_TARGETS_INVALID   = 0x40000000
	PAGE_GUARD             = 0x100
	PAGE_NOCACHE           = 0x200
	PAGE_WRITECOMBINE      = 0x400
)

var (
	TruncateLength  = 50
	HexDisplayBytes = 64
	StreamTypes     = map[int]string{
		0:          "unused",
		1:          "reserved_0",
		2:          "reserved_1",
		3:          "thread_list",
		4:          "module_list",
		5:          "memory_list",
		6:          "exception",
		7:          "system_info",
		8:          "thread_ex_list",
		9:          "memory_64_list",
		10:         "comment_a",
		11:         "comment_w",
		12:         "handle_data",
		13:         "function_table",
		14:         "unloaded_module_list",
		15:         "misc_info",
		16:         "memory_info_list",
		17:         "thread_info_list",
		18:         "handle_operation_list",
		19:         "token",
		20:         "java_script_data",
		21:         "system_memory_info",
		22:         "process_vm_counters",
		23:         "ipt_trace",
		24:         "thread_names",
		0x8000:     "ce_null",
		0x8001:     "ce_system_info",
		0x8002:     "ce_exception",
		0x8003:     "ce_module_list",
		0x8004:     "ce_process_list",
		0x8005:     "ce_thread_list",
		0x8006:     "ce_thread_context_list",
		0x8007:     "ce_thread_call_stack_list",
		0x8008:     "ce_memory_virtual_list",
		0x8009:     "ce_memory_physical_list",
		0x800A:     "ce_bucket_parameters",
		0x800B:     "ce_process_module_map",
		0x800C:     "ce_diagnosis_list",
		0x47670001: "md_raw_breakpad_info",
		0x47670002: "md_raw_assertion_info",
		0x47670003: "md_linux_cpu_info",
		0x47670004: "md_linux_proc_status",
		0x47670005: "md_linux_lsb_release",
		0x47670006: "md_linux_cmd_line",
		0x47670007: "md_linux_environ",
		0x47670008: "md_linux_auxv",
		0x47670009: "md_linux_maps",
		0x4767000a: "md_linux_dso_debug",
		0x43500001: "md_crashpad_info_stream",
	}
)

func GetMemoryProtectionString(protection uint32) string {
	protectionString := ""
	if protection&PAGE_NOACCESS != 0 || protection == 0 {
		protectionString = "PAGE_NOACCESS"
	}
	if protection&PAGE_READONLY != 0 {
		protectionString = "PAGE_READONLY"
	}
	if protection&PAGE_READWRITE != 0 {
		protectionString = "PAGE_READWRITE"
	}
	if protection&PAGE_WRITECOPY != 0 {
		protectionString = "PAGE_WRITECOPY"
	}
	if protection&PAGE_EXECUTE != 0 {
		protectionString = "PAGE_EXECUTE"
	}
	if protection&PAGE_EXECUTE_READ != 0 {
		protectionString = "PAGE_EXECUTE_READ"
	}
	if protection&PAGE_EXECUTE_READWRITE != 0 {
		protectionString = "PAGE_EXECUTE_READWRITE"
	}
	if protection&PAGE_EXECUTE_WRITECOPY != 0 {
		protectionString = "PAGE_EXECUTE_WRITECOPY"
	}

	if protectionString == "" {
		protectionString = "NONE"
	}

	return protectionString
}

func GetThreadList(dir []*parsers.WindowsMinidump_Dir) {

	var threadList *parsers.WindowsMinidump_ThreadList
	for _, stream := range dir {
		if stream.StreamType == parsers.WindowsMinidump_StreamTypes__ThreadList {
			data, err := stream.Data()
			if err != nil {
				fmt.Println(err)
			}
			threadList = data.(*parsers.WindowsMinidump_ThreadList)
			break
		}
	}

	if threadList != nil {
		tw := table.NewWriter()
		tw.AppendHeader(SliceToRow(GetTableHeader(parsers.PThread{})))
		for _, thread := range threadList.Threads {

			pthread := parsers.PThread{
				ThreadId:        thread.ThreadId,
				AddrMemoryRange: thread.Stack.AddrMemoryRange,
				SuspendCount:    thread.SuspendCount,
				Priority:        thread.Priority,
				Teb:             thread.Teb}

			tw.AppendRow(SliceToRow(GetValueAsRow(pthread)))
		}
		fmt.Println(tw.Render())
	} else {
		fmt.Println("ThreadList stream not found in the Minidump file")
	}
}

func GetMemory64List(dir []*parsers.WindowsMinidump_Dir, print bool) *parsers.WindowsMinidump_Memory64List {

	var memoryList *parsers.WindowsMinidump_Memory64List
	for _, stream := range dir {
		if stream.StreamType == parsers.WindowsMinidump_StreamTypes__Memory64List {
			data, err := stream.Data()
			if err != nil {
				fmt.Println(err)
			}
			memoryList = data.(*parsers.WindowsMinidump_Memory64List)
			break
		}
	}
	tw := table.NewWriter()
	tw.AppendHeader(SliceToRow(GetTableHeader(parsers.PMemRange{})))

	if memoryList != nil {
		for _, memRange := range memoryList.MemRanges {

			data, _ := memRange.Data()
			pmemrange := parsers.PMemRange64{
				StartOfMemoryRange: memRange.StartOfMemoryRange,
				DataSize:           memRange.LenData,
				Data:               data,
			}
			tw.AppendRow(SliceToRow(GetValueAsRow(pmemrange)))
		}
		if print {
			fmt.Println(tw.Render())
		}
	} else {
		fmt.Println("memoryList stream not found in the Minidump file")
	}

	return memoryList

}

func GetMemoryInfoList(dir []*parsers.WindowsMinidump_Dir) {

	var memoryInfoList *parsers.WindowsMinidump_MemoryInfoList
	for _, stream := range dir {
		if stream.StreamType == parsers.WindowsMinidump_StreamTypes__MemoryInfoList {
			data, err := stream.Data()
			if err != nil {
				fmt.Println(err)
			}
			memoryInfoList = data.(*parsers.WindowsMinidump_MemoryInfoList)
			break
		}
	}

	if memoryInfoList != nil {

		tw := table.NewWriter()
		tw.AppendHeader(SliceToRow(GetTableHeader(parsers.PMemInfo{})))
		for _, memRange := range memoryInfoList.Entries {

			pmeminfo := parsers.PMemInfo{
				BaseAddress: memRange.BaseAddress,
				Protect:     GetMemoryProtectionString(memRange.Protect),
				State:       memRange.State,
				Type:        memRange.Type,
				RegionSize:  memRange.RegionSize,
			}
			tw.AppendRow(SliceToRow(GetValueAsRow(pmeminfo)))
		}
		fmt.Println(tw.Render())
	} else {
		fmt.Println("memoryList stream not found in the Minidump file")
	}
}

func GetStreams(dir []*parsers.WindowsMinidump_Dir) {
	for _, stream := range dir {

		fmt.Printf("%d:%s\n", stream.StreamType, StreamTypes[int(stream.StreamType)])
	}
}

func GetSystemInfo(dir []*parsers.WindowsMinidump_Dir) {

	var systemInfo *parsers.WindowsMinidump_SystemInfo
	for _, stream := range dir {
		if stream.StreamType == parsers.WindowsMinidump_StreamTypes__SystemInfo {
			data, err := stream.Data()
			if err != nil {
				fmt.Println(err)
			}
			systemInfo = data.(*parsers.WindowsMinidump_SystemInfo)
			break
		}
	}

	tw := table.NewWriter()
	tw.AppendHeader(SliceToRow(GetTableHeader(parsers.WindowsMinidump_SystemInfo{})))
	if systemInfo != nil {
		tw.AppendRow(SliceToRow(GetValueAsRow(*systemInfo)))
		fmt.Println(tw.Render())
	}
}

func GetMiscInfo(dir []*parsers.WindowsMinidump_Dir) {
	var miscInfo *parsers.WindowsMinidump_MiscInfo
	for _, stream := range dir {
		if stream.StreamType == parsers.WindowsMinidump_StreamTypes__MiscInfo {
			data, err := stream.Data()
			if err != nil {
				fmt.Println(err)
			}
			miscInfo = data.(*parsers.WindowsMinidump_MiscInfo)
			break
		}
	}

	tw := table.NewWriter()
	tw.AppendHeader(SliceToRow(GetTableHeader(parsers.WindowsMinidump_MiscInfo{})))
	if miscInfo != nil {
		tw.AppendRow(SliceToRow(GetValueAsRow(*miscInfo)))
		fmt.Println(tw.Render())
	}
}

func GetModuleList(dir []*parsers.WindowsMinidump_Dir) {
	var moduleList *parsers.WindowsMinidump_ModuleList
	for _, stream := range dir {
		if stream.StreamType == parsers.WindowsMinidump_StreamTypes__ModuleList {
			data, err := stream.Data()
			if err != nil {
				fmt.Println(err)
			}
			moduleList = data.(*parsers.WindowsMinidump_ModuleList)
			break
		}
	}

	tw := table.NewWriter()
	tw.AppendHeader(SliceToRow(GetTableHeader(parsers.PModule{})))
	tw.SetTitle("Loaded Modules")
	if moduleList != nil {
		for _, module := range moduleList.Modules {

			moduleName, err := module.ModuleName()
			if err != nil {
				fmt.Println(err)
			}

			pmodule := parsers.PModule{
				BaseOfImage:   module.BaseOfImage,
				SizeOfImage:   module.SizeOfImage,
				CheckSum:      module.CheckSum,
				TimeDateStamp: module.TimeDateStamp,
				ModuleNameRva: module.ModuleNameRva,
				ModuleName:    moduleName,
			}
			tw.AppendRow(SliceToRow(GetValueAsRow(pmodule)))
		}
		fmt.Println(tw.Render())
	}
}

func GetUnloadedModuleList(dir []*parsers.WindowsMinidump_Dir) {
	var moduleList *parsers.WindowsMinidump_UnloadedModuleList
	for _, stream := range dir {
		if stream.StreamType == parsers.WindowsMinidump_StreamTypes__UnloadedModuleList {
			data, err := stream.Data()
			if err != nil {
				fmt.Println(err)
			}
			moduleList = data.(*parsers.WindowsMinidump_UnloadedModuleList)
			break
		}
	}

	tw := table.NewWriter()
	tw.AppendHeader(SliceToRow(GetTableHeader(parsers.PModule{})))
	tw.SetTitle("Unloaded Modules")
	if moduleList != nil {
		for _, module := range moduleList.UnloadedModules {

			moduleName, err := module.UnloadedModuleName()
			if err != nil {
				fmt.Println(err)
			}

			pmodule := parsers.PModule{
				BaseOfImage:   module.BaseOfImage,
				SizeOfImage:   module.SizeOfImage,
				CheckSum:      module.CheckSum,
				TimeDateStamp: module.TimeDateStamp,
				ModuleNameRva: module.ModuleNameRva,
				ModuleName:    moduleName,
			}
			tw.AppendRow(SliceToRow(GetValueAsRow(pmodule)))
		}
		fmt.Println(tw.Render())
	}
}

func GetHandleData(dir []*parsers.WindowsMinidump_Dir) {
	var handleData *parsers.WindowsMinidump_HandleData
	for _, stream := range dir {
		if stream.StreamType == parsers.WindowsMinidump_StreamTypes__HandleData {
			data, err := stream.Data()
			if err != nil {
				fmt.Println(err)
			}
			handleData = data.(*parsers.WindowsMinidump_HandleData)
			break
		}
	}

	tw := table.NewWriter()
	tw.AppendHeader(SliceToRow(GetTableHeader(parsers.PHandleDescriptor{})))
	tw.SetTitle("Handle Data")
	if handleData != nil {
		for _, handle := range handleData.Handles {

			phandle := parsers.PHandleDescriptor{
				Handle:        handle.Handle,
				TypeNameRva:   handle.TypeNameRva,
				ObjectNameRva: handle.ObjectNameRva,
				Attributes:    handle.Attributes,
				GrantedAccess: handle.GrantedAccess,
				CountHandle:   handle.CountHandle,
				CountPointer:  handle.CountPointer,
				ObjectInfoRva: handle.ObjectInfoRva,
			}

			handleTypeDescriptor, err := handle.TypeNameDescriptor()
			if err != nil {
				fmt.Println(err)
			} else if handleTypeDescriptor != nil {
				phandle.TypeName = handleTypeDescriptor.Str
			}

			handleObjectDescriptor, err := handle.ObjectNameDescriptor()
			if err != nil {
				fmt.Println(err)
			} else if handleObjectDescriptor != nil {
				phandle.ObjectName = handleObjectDescriptor.Str
			}
			tw.AppendRow(SliceToRow(GetValueAsRow(phandle)))
		}
		fmt.Println(tw.Render())
	}
}

func SliceToRow(data []string) table.Row {

	row := table.Row{}
	for _, value := range data {
		row = append(row, value)
	}
	return row
}

func RemoveEmptyFromEnd(slice []string) []string {
	for i := len(slice) - 1; i >= 0; i-- {
		if slice[i] != "" {
			return slice[:i+1]
		}
	}
	return []string{}
}

func GetTableHeader(data interface{}) []string {
	val := reflect.ValueOf(data)
	typ := val.Type()
	header := make([]string, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldVal := val.Field(i)

		if fieldVal.CanInterface() {
			header[i] = strings.ToUpper(field.Name)
		}
	}
	header = RemoveEmptyFromEnd(header)
	return header
}

func GetValueAsRow(data interface{}) []string {
	val := reflect.ValueOf(data)
	typ := val.Type()
	row := make([]string, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := val.Field(i)

		if field.CanInterface() {
			if field.Type().Name() == "string" {
				row[i] = fmt.Sprintf("%s", field.Interface())
			} else {
				row[i] = fmt.Sprintf("0x%x", field.Interface())
			}

			if len(row[i]) > TruncateLength {

				truncatePrefix := fmt.Sprintf("TRUNCATE%d:", TruncateLength)
				row[i] = truncatePrefix + row[i][:TruncateLength]
			}
		}
	}
	row = RemoveEmptyFromEnd(row)
	return row
}

func ReadSegment(file string, address uint64, memoryList *parsers.WindowsMinidump_Memory64List) []byte {
	currentOffset := uint64(0)

	for i, segment := range memoryList.MemRanges {

		if segment.StartOfMemoryRange == address {

			data, err := ioutil.ReadFile(file)
			if err != nil {
				fmt.Printf("Unable to read memory range %x, %v\n", address, err)
				os.Exit(-1)
			}

			SegmentRVA := memoryList.BaseRva + currentOffset
			segmentData := data[SegmentRVA : SegmentRVA+segment.LenData]
			return segmentData
		} else if i < len(memoryList.MemRanges)-1 && address > segment.StartOfMemoryRange && address < memoryList.MemRanges[i+1].StartOfMemoryRange {

			data, err := ioutil.ReadFile(file)
			if err != nil {
				fmt.Printf("Unable to read memory range %x, %v\n", address, err)
				os.Exit(-1)
			}
			additionalOffset := address - segment.StartOfMemoryRange
			SegmentRVA := memoryList.BaseRva + currentOffset + additionalOffset
			segmentData := data[SegmentRVA : SegmentRVA+segment.LenData]
			return segmentData

		} else {
			currentOffset += segment.LenData
		}
	}

	return []byte{}
}

func ScanYara(address uint64,
	memoryList *parsers.WindowsMinidump_Memory64List,
	file string,
	hexdump bool,
	yaraRules string) {

	scanner := analysis.YaraScanner{RulesPath: yaraRules}
	scanner.LoadRules()

	data := ReadSegment(file, address, memoryList)

	if len(data) > 0 {
		if hexdump {
			fmt.Println(hex.Dump(data[:HexDisplayBytes]))
		}

		matches, _ := scanner.Rules.ScanMem(data, 0, 0)
		if len(matches) > 0 {
			for _, match := range matches {
				fmt.Println(match)
			}
		} else {
			numberOfYaraRules := len(scanner.Rules.GetRules())
			fmt.Printf("No yara matches for %d rules.\n", numberOfYaraRules)
		}
	} else {
		fmt.Printf("Failed to find %x in memranges\n", address)
	}
}

func DumpMemory(address uint64,
	memoryList *parsers.WindowsMinidump_Memory64List,
	file string, dumpFile string) {

	data := ReadSegment(file, address, memoryList)
	if len(data) > 0 {
		err := ioutil.WriteFile(dumpFile, data, 0644)
		if err != nil {
			fmt.Printf("Error writing data from %x to %s\n", address, dumpFile)
		} else {
			fmt.Printf("Wrote %d bytes from %x to %s\n", len(data), address, dumpFile)
		}
	} else {
		fmt.Printf("Failed to find %x in memranges\n", address)
	}
}

func main() {

	misc.DisplayBanner()

	var cli struct {
		File string `required:"" help:"File to read the minidump from."`
		Yara struct {
			RulesPath string `required:"" name:"rules" help:"path to yara rules directory." type:"string"`
			Address   string `required:"" name:"address" help:"virtual address to scan memory." type:"string"`
			Hex       bool   `optional:"" help:"Show hex dump"`
		} `cmd:"" optional:"" help:"Yara scan at virtual address."`

		Dump struct {
			Address    string `required:"" name:"address" help:"virtual address." type:"string"`
			OutputFile string `required:"" name:"out" help:"path to extract to." type:"string"`
		} `cmd:"" optional:"" help:"Dump memory at virtual address to disk."`

		Memory struct {
		} `cmd:"" help:"Show memory."`

		Threads struct {
		} `cmd:"" help:"Show threads."`

		Streams struct {
		} `cmd:"" help:"Show streams."`

		SystemInfo struct {
		} `cmd:"" help:"Show system information."`

		Misc struct {
		} `cmd:"" help:"Show misc information."`

		Modules struct {
		} `cmd:"" help:"Show modules."`

		Handles struct {
		} `cmd:"" help:"Show handles."`

		Truncate int `optional:"" help:"Truncate long strings in table to this length." default:"50"`
	}

	ctx := kong.Parse(&cli)
	TruncateLength = cli.Truncate
	file, err := os.Open(cli.File)
	if err != nil {
		os.Exit(-1)
	}
	g := parsers.NewWindowsMinidump()
	err = g.Read(kaitai.NewStream(file), nil, g)

	dir, err := g.Streams()

	switch ctx.Command() {
	case "yara":
		formattedVal := strings.Replace(cli.Yara.Address, "0x", "", -1)
		addressValue, err := strconv.ParseInt(formattedVal, 16, 64)
		if err != nil {
			fmt.Println("Error parsing yara address:", err)
			return
		}
		memory64List := GetMemory64List(dir, false)
		ScanYara(uint64(addressValue), memory64List, cli.File, cli.Yara.Hex, cli.Yara.RulesPath)

	case "dump":
		formattedVal := strings.Replace(cli.Dump.Address, "0x", "", -1)
		addressValue, err := strconv.ParseInt(formattedVal, 16, 64)
		if err != nil {
			fmt.Println("Error parsing dump address:", err)
			return
		}
		memory64List := GetMemory64List(dir, false)
		DumpMemory(uint64(addressValue), memory64List, cli.File, cli.Dump.OutputFile)
	case "memory":
		GetMemoryInfoList(dir)

	case "threads":
		GetThreadList(dir)

	case "streams":
		GetStreams(dir)

	case "system_info":
		GetSystemInfo(dir)

	case "misc":
		GetMiscInfo(dir)

	case "modules":
		GetModuleList(dir)
		GetUnloadedModuleList(dir)

	case "handles":
		GetHandleData(dir)
	}
}
