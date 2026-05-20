# Export analysis data for Claude AI
# @author Ghidra-Claude Bridge
# @category Analysis
# @keybinding Ctrl+Shift+C
# @menupath Analysis.Export for Claude
# @toolbar

"""
Ghidra script to export comprehensive analysis data for Claude AI.
Place this file in Ghidra's scripts directory or add the directory to script paths.
"""

import json
import os
from java.io import File
from ghidra.app.decompiler import DecompInterface
from ghidra.app.util.bin.format.pe import PortableExecutable
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.task import ConsoleTaskMonitor
from java.util import ArrayList
from javax.swing import JFileChooser, JOptionPane

class ClaudeExporter:
    def __init__(self, program, monitor):
        self.program = program
        self.monitor = monitor
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(program)
        self.export_data = {}

    def export_binary_info(self):
        """Export general binary information"""
        info = {
            "name": self.program.getName(),
            "path": self.program.getExecutablePath(),
            "format": self.program.getExecutableFormat(),
            "architecture": str(self.program.getLanguageID()),
            "compiler": str(self.program.getCompilerSpec().getCompilerSpecID()),
            "endianness": "big" if self.program.getMemory().isBigEndian() else "little",
            "address_size": self.program.getAddressFactory().getDefaultAddressSpace().getSize(),
            "image_base": str(self.program.getImageBase()),
            "min_address": str(self.program.getMinAddress()),
            "max_address": str(self.program.getMaxAddress())
        }

        # Get creation/modification info
        metadata = self.program.getMetadata()
        if metadata:
            info["created"] = str(metadata.get("Date Created", "Unknown"))
            info["analyzed"] = str(metadata.get("Date Analyzed", "Unknown"))

        return info

    def export_memory_map(self):
        """Export memory sections/segments"""
        memory = self.program.getMemory()
        sections = []

        for block in memory.getBlocks():
            section = {
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize(),
                "type": block.getType().toString(),
                "permissions": {
                    "read": block.isRead(),
                    "write": block.isWrite(),
                    "execute": block.isExecute()
                },
                "initialized": block.isInitialized(),
                "mapped": block.isMapped(),
                "overlay": block.isOverlay()
            }
            sections.append(section)

        return sections

    def export_functions(self, max_functions=100):
        """Export function information with decompilation"""
        function_manager = self.program.getFunctionManager()
        functions = []
        count = 0

        for func in function_manager.getFunctions(True):
            if count >= max_functions:
                break

            # Skip external and thunk functions unless specifically interesting
            if func.isExternal():
                continue

            func_info = {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "signature": func.getPrototypeString(False, False),
                "calling_convention": func.getCallingConventionName(),
                "is_thunk": func.isThunk(),
                "is_library": func.isLibrary(),
                "has_varargs": func.hasVarArgs(),
                "stack_frame_size": func.getStackFrame().getFrameSize() if func.getStackFrame() else 0
            }

            # Get function comments
            comment = func.getComment()
            if comment:
                func_info["comment"] = comment

            # Get parameters
            params = []
            for param in func.getParameters():
                params.append({
                    "name": param.getName(),
                    "type": str(param.getDataType()),
                    "ordinal": param.getOrdinal(),
                    "storage": str(param.getVariableStorage())
                })
            func_info["parameters"] = params

            # Get local variables
            locals = []
            for var in func.getLocalVariables():
                locals.append({
                    "name": var.getName(),
                    "type": str(var.getDataType()),
                    "stack_offset": var.getStackOffset()
                })
            func_info["local_variables"] = locals

            # Get decompiled code
            decompiled = self.get_decompiled_function(func)
            if decompiled:
                func_info["decompiled_code"] = decompiled

            # Get calls from this function
            called_functions = []
            for called_func in func.getCalledFunctions(self.monitor):
                called_functions.append({
                    "name": called_func.getName(),
                    "address": str(called_func.getEntryPoint())
                })
            func_info["calls"] = called_functions

            # Get references to this function
            ref_manager = self.program.getReferenceManager()
            callers = []
            for ref in ref_manager.getReferencesTo(func.getEntryPoint()):
                from_func = self.program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
                if from_func:
                    callers.append({
                        "function": from_func.getName(),
                        "address": str(ref.getFromAddress())
                    })
            func_info["called_by"] = callers

            functions.append(func_info)
            count += 1

        return functions

    def get_decompiled_function(self, func):
        """Get decompiled C code for a function"""
        try:
            results = self.decompiler.decompileFunction(func, 30, self.monitor)
            if results.decompileCompleted():
                return results.getDecompiledFunction().getC()
        except Exception as e:
            print(f"Failed to decompile {func.getName()}: {e}")
        return None

    def export_strings(self, min_length=4, max_strings=500):
        """Export defined strings from the binary"""
        strings = []
        count = 0
        listing = self.program.getListing()

        for data in listing.getDefinedData(True):
            if count >= max_strings:
                break

            if data.hasStringValue():
                value = data.getDefaultValueRepresentation()
                if len(value) >= min_length:
                    strings.append({
                        "address": str(data.getAddress()),
                        "value": value,
                        "type": str(data.getDataType().getName()),
                        "length": len(value),
                        "references": self.get_references_to_address(data.getAddress())
                    })
                    count += 1

        return strings

    def get_references_to_address(self, address):
        """Get all references to a specific address"""
        refs = []
        ref_manager = self.program.getReferenceManager()
        for ref in ref_manager.getReferencesTo(address):
            func = self.program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
            refs.append({
                "from_address": str(ref.getFromAddress()),
                "function": func.getName() if func else None,
                "type": ref.getReferenceType().getName()
            })
        return refs

    def export_imports_exports(self):
        """Export imported and exported symbols"""
        symbol_table = self.program.getSymbolTable()
        imports = []
        exports = []

        for symbol in symbol_table.getAllSymbols(True):
            sym_info = {
                "name": symbol.getName(),
                "address": str(symbol.getAddress()),
                "type": symbol.getSymbolType().toString()
            }

            if symbol.isExternal():
                # Import
                external_loc = symbol.getProgram().getExternalManager().getExternalLocation(symbol)
                if external_loc:
                    sym_info["library"] = external_loc.getLibraryName()
                imports.append(sym_info)
            elif symbol.getSource() == SourceType.EXPORTED:
                # Export
                exports.append(sym_info)

        return {"imports": imports, "exports": exports}

    def export_interesting_patterns(self):
        """Identify interesting code patterns for security analysis"""
        patterns = {
            "crypto_functions": [],
            "network_functions": [],
            "file_operations": [],
            "memory_operations": [],
            "string_operations": [],
            "suspicious_functions": [],
            "registry_operations": [],
            "process_thread_operations": [],
            "anti_debug_techniques": [],
            "privilege_escalation": [],
            "com_ole_operations": [],
            "wmi_operations": []
        }

        # Define pattern keywords (expanded for comprehensive detection)
        crypto_keywords = [
            # Symmetric ciphers
            "crypt", "aes", "des", "3des", "tdes", "blowfish", "twofish", "serpent",
            "camellia", "rc4", "rc5", "rc6", "chacha", "salsa", "aria", "seed", "cast",
            # Asymmetric/PKI
            "rsa", "dsa", "ecdsa", "ecdh", "diffie", "hellman", "elgamal", "curve25519",
            "ed25519", "x25519", "secp256", "nistp", "pubkey", "privkey", "keypair",
            # Hashing
            "sha", "sha1", "sha256", "sha384", "sha512", "sha3", "md4", "md5", "md6",
            "hash", "digest", "hmac", "pbkdf", "scrypt", "argon2", "bcrypt", "keccak",
            "blake2", "blake3", "ripemd", "whirlpool", "tiger", "crc32", "checksum",
            # General crypto
            "cipher", "encrypt", "decrypt", "encipher", "decipher", "crypto", "ssl",
            "tls", "x509", "certificate", "sign", "verify", "pkcs", "pem", "der",
            "base64", "encode", "decode", "iv", "nonce", "salt", "key", "secret",
            "random", "rand", "entropy", "prng", "drbg", "openssl", "botan", "sodium",
            "gcm", "cbc", "ecb", "ctr", "cfb", "ofb", "xts", "ccm", "ocb", "padding"
        ]
        network_keywords = [
            # Socket operations
            "socket", "sock", "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg",
            "connect", "bind", "listen", "accept", "shutdown", "closesocket", "select",
            "poll", "epoll", "kqueue", "ioctl", "getsockopt", "setsockopt", "getsockname",
            "getpeername", "socketpair",
            # Network addressing
            "inet", "addr", "ntohl", "htonl", "ntohs", "htons", "getaddrinfo", "getnameinfo",
            "gethostbyname", "gethostbyaddr", "getservbyname", "getservbyport", "dns",
            "resolve", "lookup", "ipv4", "ipv6",
            # Protocols
            "http", "https", "ftp", "sftp", "ssh", "telnet", "smtp", "pop3", "imap",
            "tcp", "udp", "icmp", "raw", "packet", "ethernet", "arp", "dhcp", "snmp",
            "ldap", "kerberos", "ntlm", "socks", "proxy", "websocket", "mqtt", "amqp",
            # High-level networking
            "curl", "wget", "urlopen", "request", "response", "download", "upload",
            "transfer", "fetch", "post", "get", "put", "patch", "delete", "api",
            "rest", "soap", "rpc", "grpc", "thrift", "protobuf",
            # Windows networking
            "winsock", "wsastartup", "wsacleanup", "wsasend", "wsarecv", "wininet",
            "winhttp", "internetopen", "internetconnect", "httpopen", "httpsend",
            "urldownload", "inetaddr"
        ]
        file_keywords = [
            # Basic file operations
            "open", "close", "read", "write", "seek", "tell", "flush", "sync",
            "create", "delete", "remove", "unlink", "rename", "copy", "move",
            "file", "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "fflush",
            "fgets", "fputs", "fgetc", "fputc", "fprintf", "fscanf", "feof", "ferror",
            # Directory operations
            "directory", "dir", "mkdir", "rmdir", "chdir", "getcwd", "opendir",
            "readdir", "closedir", "scandir", "listdir", "walkdir", "glob", "find",
            # Path operations
            "path", "realpath", "basename", "dirname", "abspath", "relpath", "exists",
            "isfile", "isdir", "islink", "stat", "fstat", "lstat", "access", "chmod",
            "chown", "truncate", "utime", "touch",
            # Windows file API
            "createfile", "readfile", "writefile", "deletefile", "copyfile", "movefile",
            "setfilepointer", "getfilesize", "getfiletype", "getfileattributes",
            "setfileattributes", "findfirstfile", "findnextfile", "findclose",
            "gettempppath", "gettempfilename", "getcurrentdirectory", "setcurrentdirectory",
            # Memory-mapped files
            "mmap", "munmap", "mprotect", "msync", "createfilemapping", "mapviewoffile",
            "unmapviewoffile", "flushviewoffile"
        ]
        memory_keywords = [
            # Standard C allocation
            "alloc", "malloc", "calloc", "realloc", "free", "memalign", "posix_memalign",
            "aligned_alloc", "valloc", "pvalloc", "reallocarray",
            # C++ allocation
            "new", "delete", "new[]", "delete[]", "operator new", "operator delete",
            # Heap operations
            "heap", "heapalloc", "heapfree", "heaprealloc", "heapcreate", "heapdestroy",
            "heapsize", "heapvalidate", "heapcompact", "heaplock", "heapunlock",
            "getprocessheap", "heapwalk",
            # Virtual memory
            "virtualalloc", "virtualfree", "virtualprotect", "virtualquery", "virtuallock",
            "virtualunlock", "virtualallocex", "virtualfreeex", "virtualprotectex",
            "virtualqueryex",
            # Memory operations
            "memcpy", "memmove", "memset", "memcmp", "memchr", "memrchr", "memmem",
            "bcopy", "bzero", "explicit_bzero", "securezeromemory",
            # Memory mapping
            "mmap", "munmap", "mprotect", "mlock", "munlock", "mlockall", "munlockall",
            "mremap", "msync", "mincore", "madvise",
            # Windows memory
            "globalalloc", "globalfree", "globallock", "globalunlock", "globalrealloc",
            "localalloc", "localfree", "locallock", "localunlock", "localrealloc",
            "copymemory", "movememory", "fillmemory", "zeromemory", "rtlmovememory",
            "rtlcopymemory", "rtlzeromemory", "rtlfillmemory"
        ]
        string_keywords = [
            # Dangerous/unsafe functions
            "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
            "vscanf", "vsscanf", "strtok", "realpath",
            # Bounded versions (still review-worthy)
            "strncpy", "strncat", "snprintf", "vsnprintf", "fgets", "strtok_r",
            # String operations
            "strlen", "strcmp", "strncmp", "strchr", "strrchr", "strstr", "strnstr",
            "strspn", "strcspn", "strpbrk", "strsep", "strdup", "strndup",
            # Wide string operations
            "wcscpy", "wcscat", "wcslen", "wcscmp", "wcsncpy", "wcsncat", "wcsncmp",
            "wcschr", "wcsrchr", "wcsstr", "wcsspn", "wcscspn", "wcspbrk", "wcstok",
            "wprintf", "wsprintf", "swprintf", "vswprintf",
            # Windows string functions
            "lstrcpy", "lstrcat", "lstrlen", "lstrcmp", "lstrcmpi", "lstrcpyn",
            "wsprintfa", "wsprintfw", "wnsprintfa", "wnsprintfw",
            "stringcchcopy", "stringcchcat", "stringcbcopy", "stringcbcat",
            "rtlstringcchcopy", "rtlstringcchcat",
            # Format string related
            "printf", "fprintf", "dprintf", "vprintf", "vfprintf", "vdprintf",
            "syslog", "err", "errx", "warn", "warnx", "setproctitle",
            # Case conversion
            "toupper", "tolower", "strupr", "strlwr", "_strupr", "_strlwr",
            "towupper", "towlower"
        ]
        suspicious_keywords = [
            # Code injection
            "hook", "inject", "injection", "detour", "trampoline", "patch", "hotpatch",
            "inline_hook", "iat_hook", "eat_hook", "ssdt_hook", "syscall_hook",
            "dll_inject", "code_inject", "shellcode", "payload", "stub", "cave",
            # Process manipulation
            "createremotethread", "ntcreatethreadex", "rtlcreateuserthread",
            "queueuserapc", "ntqueueapcthread", "setthreadcontext", "getthreadcontext",
            "suspendthread", "resumethread", "terminatethread", "terminateprocess",
            "openprocess", "writeprocessmemory", "readprocessmemory", "ntwritevirtualmemory",
            "ntreadvirtualmemory", "ntallocatevirtualmemory", "createprocess",
            "hollowing", "process_hollow", "runpe", "reflective",
            # Hiding/evasion
            "hide", "hidden", "stealth", "cloak", "unlink", "rootkit", "bootkit",
            "dkom", "direct_kernel", "ssdt", "idt", "gdt", "msr",
            # Persistence
            "persist", "autorun", "startup", "runonce", "service", "scheduled_task",
            "registry_run", "userinit", "winlogon", "appinit", "lsa", "com_hijack",
            "dll_hijack", "search_order", "phantom_dll", "wmi_persist",
            # Keylogging/capture
            "keylog", "keylogger", "getasynckeystate", "getkeystate", "getkeyboardstate",
            "setwindowshook", "setwindowshookex", "callnexthookex", "unhookwindowshookex",
            "rawinput", "getclipboard", "clipboard", "screen_capture", "screenshot",
            # Network malware indicators
            "backdoor", "reverse_shell", "bind_shell", "c2", "command_control", "beacon",
            "exfil", "exfiltrate", "phonehome", "callback", "dropper", "downloader",
            "stager", "implant", "rat", "botnet", "zombie",
            # Anti-analysis
            "antidebug", "anti_debug", "isdebuggerpresent", "checkremotedebuggerpresent",
            "ntqueryinformationprocess", "debugactiveprocess", "outputdebugstring",
            "int3", "int2d", "ice", "trap_flag", "timing_check", "rdtsc",
            "antivm", "anti_vm", "vmware", "virtualbox", "vbox", "qemu", "hyperv",
            "sandbox", "sandboxie", "cuckoo", "anubis", "joe_sandbox",
            "cpuid", "in_instruction", "sidt", "sgdt", "sldt", "str",
            # Crypter/packer indicators
            "unpack", "unpacker", "decrypt_payload", "deobfuscate", "decode_stub",
            "self_modify", "polymorphic", "metamorphic", "crypter", "packer",
            "upx", "aspack", "pecompact", "themida", "vmprotect", "enigma",
            # Credential theft
            "mimikatz", "lsass", "sam", "ntds", "credential", "password", "hash_dump",
            "pass_the_hash", "golden_ticket", "silver_ticket", "kerberoast", "dcsync"
        ]
        registry_keywords = [
            # Registry key operations
            "regopen", "regclose", "regcreate", "regdelete", "regquery", "regset",
            "regenumkey", "regenumvalue", "regflushkey", "regloadkey", "regunloadkey",
            "regsavekey", "regrestorekey", "regconnectregistry", "regnotifychangekeyvalue",
            # Full API names
            "regopenkeyex", "regcreatekeyex", "regdeletekeyex", "regdeletevalue",
            "regqueryvalueex", "regsetvalueex", "regenumkeyex", "regenumvalueex",
            "reggetvalue", "regsetkeysecurity", "reggetkeysecurity",
            # NT API
            "ntopenkey", "ntcreatekey", "ntdeletekey", "ntquerykey", "ntsetvaluekey",
            "ntqueryvaluekey", "ntenumeratekey", "ntenumeratevaluekey", "ntflushkey",
            "zwopenkey", "zwcreatekey", "zwdeletekey", "zwquerykey", "zwsetvaluekey",
            # Registry hives and paths
            "hkey_local_machine", "hkey_current_user", "hkey_classes_root",
            "hkey_users", "hkey_current_config", "hklm", "hkcu", "hkcr",
            # Common persistence locations
            "currentversion\\run", "currentversion\\runonce", "winlogon",
            "shell\\open\\command", "software\\microsoft", "system\\currentcontrolset"
        ]
        process_thread_keywords = [
            # Process creation
            "createprocess", "createprocessa", "createprocessw", "createprocessasuser",
            "createprocesswithlogon", "createprocesswithtokenw", "winexec", "shellexecute",
            "shellexecutea", "shellexecutew", "shellexecuteex", "system", "popen", "_popen",
            # NT process APIs
            "ntcreateprocess", "ntcreateuserprocess", "rtlcreateuserprocess",
            "zwcreateprocess", "zwcreateuserprocess", "ntopenprocess", "zwopenprocess",
            # Process manipulation
            "openprocess", "terminateprocess", "getexitcodeprocess", "getprocessid",
            "getcurrentprocess", "getcurrentprocessid", "getprocessheap",
            "enumprocesses", "enumprocessmodules", "getmodulebasename", "getmodulefilename",
            "queryfullinformationprocess", "ntqueryinformationprocess",
            # Thread creation
            "createthread", "createremotethread", "createremotethreadex",
            "ntcreatethread", "ntcreatethreadex", "rtlcreateuserthread",
            "zwcreatethread", "zwcreatethreadex",
            # Thread manipulation
            "openthread", "suspendthread", "resumethread", "terminatethread",
            "getthreadcontext", "setthreadcontext", "getthreadid", "getcurrentthread",
            "getcurrentthreadid", "switchtothread", "sleep", "sleepex", "waitforsingleobject",
            "waitformultipleobjects", "ntdelayexecution",
            # APC injection
            "queueuserapc", "ntqueueapcthread", "ntqueueapcthreadex",
            # Process/thread info
            "ntqueryinformationthread", "ntsetinformationthread",
            "ntqueryinformationprocess", "ntsetinformationprocess",
            # Job objects
            "createjobobject", "assignprocesstojobobject", "terminatejobobject"
        ]
        anti_debug_keywords = [
            # Windows anti-debug APIs
            "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
            "ntsetinformationthread", "debugactiveprocess", "debugactiveprocessstop",
            "outputdebugstring", "debugbreak", "raiseexception",
            # Debug flags and checks
            "processdebuginformation", "processdebugobjecthandle", "processdebugflags",
            "threadhidefromdebugger", "debugobject", "ntqueryobject",
            # Timing-based detection
            "rdtsc", "queryperformancecounter", "queryperformancefrequency",
            "gettickcount", "gettickcount64", "timegettime", "ntquerysystemtime",
            "timing_check", "time_delta",
            # Exception-based detection
            "setunhandledexceptionfilter", "addvectoredexceptionhandler",
            "removevectoredexceptionhandler", "ntcontinue", "kiuserexceptiondispatcher",
            # Hardware breakpoint detection
            "getthreadcontext", "setthreadcontext", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
            # INT instructions
            "int3", "int1", "int2d", "icebp", "int0x2d", "trap_flag",
            # Parent process checks
            "getparentprocess", "ntqueryinformationprocess",
            # Window/class detection
            "findwindow", "findwindowa", "findwindoww", "findwindowex",
            "enumwindows", "getwindowtext", "getclassname",
            # Anti-VM techniques (also in suspicious but critical for anti-debug)
            "cpuid", "sidt", "sgdt", "sldt", "smsw", "str", "in_instruction",
            "vmware", "virtualbox", "vbox", "qemu", "hyperv", "xen", "parallels",
            # Process enumeration for debugger detection
            "createtoolhelp32snapshot", "process32first", "process32next",
            "module32first", "module32next", "thread32first", "thread32next",
            # Self-debugging
            "ntsetinformationprocess", "processinstrumentationcallback"
        ]
        privilege_escalation_keywords = [
            # Token manipulation
            "openprocesstoken", "openthreadtoken", "duplicatetoken", "duplicatetokenex",
            "impersonateloggedonuser", "impersonatenamedpipeclient", "impersonateself",
            "setthreadtoken", "adjusttokenprivileges", "adjusttokengroups",
            "gettokeninformation", "settokeninformation", "createrestrictedtoken",
            "impersonateanonymoustoken", "reverttoself",
            # Privilege constants
            "se_debug_privilege", "se_assignprimarytoken_privilege", "se_tcb_privilege",
            "se_security_privilege", "se_take_ownership_privilege", "se_load_driver_privilege",
            "se_backup_privilege", "se_restore_privilege", "se_shutdown_privilege",
            "se_impersonate_privilege", "se_increase_quota_privilege",
            # Privilege lookup
            "lookupprivilegevalue", "lookupprivilegename", "privilegecheck",
            # SID and security descriptor
            "allocateandinitializesid", "initializesid", "getsidsubauthority",
            "equalsid", "copysid", "lookupaccountsid", "lookupaccountname",
            "getsecuritydescriptorowner", "setsecuritydescriptorowner",
            "initializesecuritydescriptor", "setsecuritydescriptordacl",
            # Access control
            "checktokenmembership", "accesscheck", "privobjectauditcheck",
            "getsecurityinfo", "setsecurityinfo", "getacl", "setacl",
            # UAC bypass indicators
            "uac", "autoelevate", "runas", "elevated", "highintigrity",
            "cmstp", "fodhelper", "eventvwr", "sdclt", "silentcleanup",
            # Named pipe impersonation
            "createnamedpipe", "connectnamedpipe", "impersonatenamedpipeclient",
            # Service manipulation
            "openscmanager", "createservice", "openservice", "startservice",
            "controlservice", "deleteservice", "changeserviceconfig",
            "queryservicestatus", "enumservicesstatus"
        ]
        com_ole_keywords = [
            # COM initialization
            "coinitialize", "coinitializeex", "couninitialize", "coinitializesecurity",
            # Object creation
            "cocreateinstance", "cocreateinstanceex", "cogetclassobject",
            "cogetinstancefromfile", "cogetinstancefromistorage",
            # CLSID/ProgID
            "clsidfromprogid", "clsidfromstring", "progidfromclsid", "stringfromclsid",
            # Interface operations
            "queryinterface", "addref", "release", "queryservice",
            # Marshaling
            "comarshalinterface", "counmarshalinterface", "comarshalhresult",
            "coreleasemarshaldata", "cogetmarshalsizgmax",
            # Moniker
            "mkparsedisplayname", "createbindctx", "createitemoniker",
            "createfilemoniker", "createclassmoniker", "bindmoniker",
            # OLE Automation
            "iunknown", "idispatch", "invoke", "QueryInterface", "QueryDispatch",
            "QueryAutomation", "QueryInterface", "QueryAutoInterface",
            "QueryIDispatch", "QueryIDispatchEx",
            # Variant/SafeArray (used in COM)
            "variantinit", "variantclear", "variantcopy", "variantchangetype",
            "safearraycreate", "safearrayaccessdata", "safearrayunaccessdata",
            # Type library
            "loadtypelib", "loadtypelibex", "registertypelib", "unregistertypelib",
            # COM server
            "dllgetclassobject", "dllcanunloadnow", "dllregisterserver", "dllunregisterserver",
            # DCOM
            "cosetproxyblanket", "coqueryproxyblanket", "cocopyproxy",
            # COM hijacking indicators
            "inprocserver32", "localserver32", "treatss", "clsid",
            # Scripting objects often abused
            "wscript", "cscript", "scriptcontrol", "msscriptcontrol",
            "shell.application", "wscript.shell", "scripting.filesystemobject"
        ]
        wmi_keywords = [
            # WMI connection
            "connectserver", "execquery", "execnotificationquery", "execmethod",
            "iwbemservices", "iwbemlocator", "iwbemclassobject", "iwbemcontext",
            # WMI query language
            "wql", "select", "from", "where", "win32_", "__instancecreationevent",
            "__instancemodificationevent", "__instancedeletionevent",
            # Common WMI classes for enumeration
            "win32_process", "win32_service", "win32_computersystem",
            "win32_operatingsystem", "win32_logicaldisk", "win32_networkadapter",
            "win32_useraccount", "win32_group", "win32_share", "win32_product",
            "win32_bios", "win32_baseboard", "win32_processor",
            # WMI process creation (common in malware)
            "win32_process", "create", "commandline", "processid",
            # WMI persistence
            "__eventfilter", "__eventconsumer", "__filtertoconsumerbinding",
            "activescripteventconsumer", "commandlineeventconsumer",
            # WMI security
            "win32_securitydescriptor", "win32_ace", "win32_trustee",
            # WMIC indicators
            "wmic", "wbem", "cimv2", "root\\cimv2", "root\\default",
            "root\\subscription", "root\\security",
            # WMI namespaces
            "managementobject", "managementclass", "managementscope",
            # Anti-forensics WMI
            "win32_shadowcopy", "win32_volume"
        ]

        function_manager = self.program.getFunctionManager()
        for func in function_manager.getFunctions(True):
            func_name_lower = func.getName().lower()

            func_data = {
                "name": func.getName(),
                "address": str(func.getEntryPoint())
            }

            # Categorize based on function name
            if any(keyword in func_name_lower for keyword in crypto_keywords):
                patterns["crypto_functions"].append(func_data)
            if any(keyword in func_name_lower for keyword in network_keywords):
                patterns["network_functions"].append(func_data)
            if any(keyword in func_name_lower for keyword in file_keywords):
                patterns["file_operations"].append(func_data)
            if any(keyword in func_name_lower for keyword in memory_keywords):
                patterns["memory_operations"].append(func_data)
            if any(keyword in func_name_lower for keyword in string_keywords):
                patterns["string_operations"].append(func_data)
            if any(keyword in func_name_lower for keyword in suspicious_keywords):
                patterns["suspicious_functions"].append(func_data)
            if any(keyword in func_name_lower for keyword in registry_keywords):
                patterns["registry_operations"].append(func_data)
            if any(keyword in func_name_lower for keyword in process_thread_keywords):
                patterns["process_thread_operations"].append(func_data)
            if any(keyword in func_name_lower for keyword in anti_debug_keywords):
                patterns["anti_debug_techniques"].append(func_data)
            if any(keyword in func_name_lower for keyword in privilege_escalation_keywords):
                patterns["privilege_escalation"].append(func_data)
            if any(keyword in func_name_lower for keyword in com_ole_keywords):
                patterns["com_ole_operations"].append(func_data)
            if any(keyword in func_name_lower for keyword in wmi_keywords):
                patterns["wmi_operations"].append(func_data)

        return patterns

    def export_control_flow_info(self):
        """Export control flow and basic block information for key functions"""
        control_flow = []
        function_manager = self.program.getFunctionManager()
        count = 0

        for func in function_manager.getFunctions(True):
            if count >= 20:  # Limit to 20 functions
                break
            if func.isExternal() or func.isThunk():
                continue

            func_cf = {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "basic_blocks": [],
                "cyclomatic_complexity": self.calculate_cyclomatic_complexity(func)
            }

            # Get basic blocks
            basic_block_model = self.program.getBasicBlockModel()
            blocks = basic_block_model.getCodeBlocksContaining(func.getBody(), self.monitor)
            while blocks.hasNext():
                block = blocks.next()
                block_info = {
                    "start": str(block.getMinAddress()),
                    "end": str(block.getMaxAddress()),
                    "size": block.getNumAddresses()
                }
                func_cf["basic_blocks"].append(block_info)

            control_flow.append(func_cf)
            count += 1

        return control_flow

    def calculate_cyclomatic_complexity(self, func):
        """Calculate cyclomatic complexity of a function"""
        # Simplified calculation: count decision points
        complexity = 1
        listing = self.program.getListing()
        instructions = listing.getInstructions(func.getBody(), True)

        branch_mnemonics = ["JMP", "JE", "JNE", "JZ", "JNZ", "JG", "JGE", "JL", "JLE",
                           "JA", "JAE", "JB", "JBE", "CALL", "RET"]

        for instr in instructions:
            if any(instr.getMnemonicString().upper().startswith(mnem) for mnem in branch_mnemonics):
                complexity += 1

        return complexity

    def export_all(self):
        """Export all analysis data"""
        print("Exporting binary information...")
        self.export_data["binary_info"] = self.export_binary_info()

        print("Exporting memory map...")
        self.export_data["memory_map"] = self.export_memory_map()

        print("Exporting functions...")
        self.export_data["functions"] = self.export_functions()

        print("Exporting strings...")
        self.export_data["strings"] = self.export_strings()

        print("Exporting imports/exports...")
        ie_data = self.export_imports_exports()
        self.export_data["imports"] = ie_data["imports"]
        self.export_data["exports"] = ie_data["exports"]

        print("Identifying interesting patterns...")
        self.export_data["patterns"] = self.export_interesting_patterns()

        print("Exporting control flow information...")
        self.export_data["control_flow"] = self.export_control_flow_info()

        return self.export_data

    def save_to_file(self, filepath):
        """Save exported data to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.export_data, f, indent=2)
        print(f"Export complete: {filepath}")

def main():
    """Main execution function"""
    monitor = ConsoleTaskMonitor()
    exporter = ClaudeExporter(currentProgram, monitor)

    # Ask user where to save the export
    chooser = JFileChooser()
    chooser.setDialogTitle("Save Claude Export")
    chooser.setSelectedFile(File(currentProgram.getName() + "_claude_export.json"))

    if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
        output_file = chooser.getSelectedFile().getAbsolutePath()

        print("Starting export for Claude AI analysis...")
        exporter.export_all()
        exporter.save_to_file(output_file)

        JOptionPane.showMessageDialog(None,
            f"Export complete!\nFile saved to: {output_file}\n\nYou can now use this file with the Claude AI integration.",
            "Export Successful",
            JOptionPane.INFORMATION_MESSAGE)
    else:
        print("Export cancelled by user")

if __name__ == "__main__":
    main()