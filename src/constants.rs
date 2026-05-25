pub const RADARE_EXECUTABLE_NAME: &str = "radare2";

pub const NTOSKRNL_DEFAULT_EXECUTABLE_FILE: &str = "C:/Windows/System32/ntoskrnl.exe";

pub const SEMANTIC_VERSIONING_REGEX: &str =
    r"(0|(?:[1-9]\d*))(?:\.(0|(?:[1-9]\d*))(?:\.(0|(?:[1-9]\d*)))?(?:\-([\w][\w\.\-_]*))?)?";

pub const OFFSETS_REGEX: &str = r"0x[a-f0-9]+";

pub type StructWithCondition = [&'static str; 2];

pub const EXPECTED_SYMBOLS: [StructWithCondition; 63] = [
    ["_LIST_ENTRY ActiveProcessLinks", ""],
    ["void * UniqueProcessId", ""],
    ["_LIST_ENTRY ThreadListHead", "struct _EPROCESS"],
    ["_PS_PROTECTION Protection", ""],
    ["_EX_FAST_REF Token", ""],
    ["_HANDLE_TABLE* ObjectTable", ""],
    ["char ImageFileName[15]", "struct _EPROCESS"],
    ["_PEB* Peb", "struct _EPROCESS"],
    ["int64_t CreateTime", "struct _EPROCESS"],
    ["int64_t ExitTime", "struct _EPROCESS"],
    ["_MMSUPPORT* Vm", "struct _EPROCESS"],
    ["uint32_t Flags", "struct _EPROCESS"],
    ["uint32_t DebugPort", "struct _EPROCESS"],
    ["uint32_t ExceptionPort", "struct _EPROCESS"],
    ["uint32_t Wow64Process", "struct _EPROCESS"],
    ["_KTRAP_FRAME* TrapFrame", "struct _KTHREAD"],
    ["_LIST_ENTRY ThreadListEntry", "struct _ETHREAD"],
    ["_CLIENT_ID Cid", ""],
    ["void* StartAddress", "struct _ETHREAD"],
    ["void* Win32StartAddress", "struct _ETHREAD"],
    ["int64_t KernelTime", "struct _KTHREAD"],
    ["int64_t UserTime", "struct _KTHREAD"],
    ["uint32_t ContextSwitches", "struct _KTHREAD"],
    ["uint32_t Priority", "struct _KTHREAD"],
    ["uint32_t BasePriority", "struct _KTHREAD"],
    ["_KWAIT_BLOCK* WaitBlockList", "struct _KTHREAD"],
    ["_KAPC_STATE ApcState", "struct _KTHREAD"],
    ["_KQUEUE* ApcQueueLock", "struct _KTHREAD"],
    ["_KAPC* CallbackStack", "struct _KTHREAD"],
    ["EtwThreatIntProvRegHandle", ""],
    ["_ETW_GUID_ENTRY* GuidEntry", ""],
    ["_TRACE_ENABLE_INFO ProviderEnableInfo", ""],
    ["_GUID Guid", "struct _ETW_GUID_ENTRY"],
    ["_KPCR* KernelProcessorControlBlock", ""],
    ["uint32_t CurrentPrcb", "struct _KPCR"],
    ["uint32_t CurrentThread", "struct _KPCR"],
    ["uint32_t IdleThread", "struct _KPCR"],
    ["_LIST_ENTRY ReadyListHead", "struct _KPRCB"],
    ["_LIST_ENTRY PsLoadedModuleList", ""],
    ["void* MmPfnDatabase", ""],
    ["void* HalDispatchTable", ""],
    ["void* KiServiceTable", ""],
    ["uint64_t KdDebuggerDataBlock", ""],
    ["uint64_t KdVersionBlock", ""],
    ["uint64_t SystemCall", "struct _KUSER_SHARED_DATA"],
    ["uint32_t TickCount", "struct _KUSER_SHARED_DATA"],
    ["uint32_t TickCountMultiplier", "struct _KUSER_SHARED_DATA"],
    ["uint32_t DirectoryTableBase", "struct _KPROCESS"],
    ["_LIST_ENTRY ProcessListEntry", "struct _KPROCESS"],
    ["uint64_t PageFrameNumber", "struct _MMPTE"],
    ["uint64_t Valid", "struct _MMPTE"],
    ["_TOKEN_SOURCE TokenSource", "struct _TOKEN"],
    ["uint32_t Privileges", "struct _TOKEN"],
    ["_DRIVER_OBJECT* DriverObject", ""],
    ["_DEVICE_OBJECT* DeviceObject", ""],
    ["_IRP* CurrentIrp", "struct _DEVICE_OBJECT"],
    ["uint32_t SignalState", "struct _KEVENT"],
    ["_LIST_ENTRY WaitListHead", "struct _KQUEUE"],
    ["_KSPIN_LOCK SpinLock", "struct _ERESOURCE"],
    ["_FAST_MUTEX FastMutex", ""],
    ["_KAPC* ApcListHead", "struct _KPRCB"],
    ["_KTIMER Timer", ""],
    ["uint64_t DueTime", "struct _KTIMER"],
];

pub const EXPECTED_FILE_VERSION_INFO: &str = "FileVersion:";

pub const EXPECTED_RADARE_MAJOR_VERSION: i8 = 5;