# Wine/Proton Debugging Workflow

This guide shows how to systematically diagnose Windows application compatibility issues using static analysis and Wine debug logs.

## The Problem

Your Windows application doesn't work in Wine/Proton. You see:
- Black screen
- Crash on startup
- Graphics glitches
- Networking failure
- Missing DLLs

How do you figure out what went wrong?

---

## Diagnosis Workflow

### Step 1: Understand What the Binary Needs (Static Analysis)

**Run:** `pe_inspector.py`

```bash
python3 tools/pe_inspector.py path/to/app.exe
```

**Look for:**
- Architecture (x86 vs x86-64) — Wine must support this
- Subsystem (GUI vs Console)
- Sections (.text, .data, .reloc, etc.)
- **Imported DLLs** — This tells you what dependencies exist

**Example output interpretation:**
```
Imports: kernel32, user32, d3d9, dxgi, opengl32, winsock2
```

This tells you:
- Needs basic Windows API (kernel32, user32) → Wine should handle
- Needs DirectX 9 (d3d9, dxgi) → Requires DXVK/VKD3D
- Needs graphics (opengl32) → May need GPU drivers
- Needs networking (winsock2) → Wine has this, but may need config

---

### Step 2: See How a Loader Would Arrange It (Memory Model)

**Run:** `pe_mapper.py`

```bash
python3 tools/pe_mapper.py path/to/app.exe
```

**Look for:**
- Image base and size — Is relocation needed?
- Section layout — Where does code/data go?
- Import table structure — How many DLLs, how many functions?
- Any suspicious patterns

**Key insight:**
```
STEP 2 — Reserve virtual address space
  Preferred image base : 0x0000000000400000
  Total image size     : 0x00040000  (262,144 bytes)
```

This is the "contract" the binary expects. Wine must provide this memory layout.

**If image base conflicts:**
```
.reloc section with relocations present
```

Wine will rebase the binary to a different address if needed.

---

### Step 3: Actually Try to Run It and Capture Debug Output

**Generate debug log:**

```bash
# Create debug.log with all important events
WINEDEBUG=+loaddll,+seh,+timestamp wine path/to/app.exe 2>&1 | tee debug.log

# Or with more verbose output:
WINEDEBUG=+loaddll,+seh,+timestamp,+warn wine path/to/app.exe 2>&1 | tee debug.log
```

Let the app run (or crash) for a few seconds, then Ctrl+C.

---

### Step 4: Analyze the Debug Log

**Run:** `wine_debug_analyzer.py`

```bash
python3 tools/wine_debug_analyzer.py debug.log
```

**Examine the output:**

#### 4a. Check What Loaded

```
DLLs Loaded: 42
  ├── kernel32.dll
  ├── ntdll.dll
  ├── user32.dll
  └── 39 others
```

If everything you need from Step 1 shows up here → Good sign.

#### 4b. Check for Missing DLLs

```
Missing DLLs: 1
  ✗ d3dcompiler_47.dll
```

This is **critical**. If a required DLL didn't load, the application cannot run.

**Action if missing:**
```bash
# Try installing it via DXVK/VKD3D package manager
sudo apt install dxvk-vkd3d      # Debian/Ubuntu
pacman -S dxvk                   # Arch

# Or update Proton (which bundles these)
```

#### 4c. Check for Warnings

```
Warnings: 8
  [1] FAILED to set new screen mode! Falling back to 1920x1080.
  [2] Format WINED3DFMT_P8_RGB not supported by device
  [3] Cannot find Vulkan driver
  [4] Unimplemented feature level 12_1
```

Warnings often predict failures. Look for patterns:
- **Graphics warnings** → GPU/driver issue, use DXVK
- **Audio warnings** → Audio subsystem issues
- **Networking warnings** → Winsock/network config
- **Threading warnings** → Concurrency issues

#### 4d. Check for Errors

```
Errors: 5
  [1] Cannot allocate device-local memory for resource
  [2] Cannot find dll "d3dcompiler_47.dll"
  [3] Unhandled exception in thread 0024:002c
  [4] Cannot create input context
  [5] Heap block damaged
```

Errors are usually why the app stops. Each error points to a layer:
- **Memory errors** → System RAM/VRAM issues
- **DLL errors** → Missing dependency
- **Exception errors** → Likely crash point
- **Input/context errors** → UI or device issues

#### 4e. Check First Failure

```
First Failure:
  Line: 134
  err:d3d:resource_init Cannot allocate device-local memory for resource
```

This is often the actual blocker. Everything before this usually succeeded.

#### 4f. Estimated Category

```
Estimated Category: Graphics Compatibility Issue
  → Likely needs: DXVK, VKD3D, or GPU driver update
```

This narrows down where to look.

---

## Common Issues and Solutions

### Issue: "Cannot find dll 'XXXX.dll'"

**Diagnosis:**
```
Missing DLLs: 1
  ✗ d3dcompiler_47.dll
```

**Cause:** Required DLL not installed in Wine prefix.

**Fix:**
```bash
# Option 1: Install via package manager
sudo apt install wine-32 wine-64 dxvk

# Option 2: Use winetricks
winetricks d3dx9

# Option 3: Copy from Windows (if you have access)
cp /path/to/windows/system32/d3dcompiler_47.dll ~/.wine/drive_c/windows/system32/
```

---

### Issue: "Graphics Compatibility Issue" + "Cannot find Vulkan driver"

**Diagnosis:**
```
Warnings: 3
  [1] Cannot find Vulkan driver
  [2] Cannot allocate device-local memory for resource
  [3] Unimplemented feature level 12_1

Estimated Category: Graphics Compatibility Issue
```

**Cause:** GPU drivers not installed or DXVK not available.

**Fix:**
```bash
# Update GPU drivers
# Ubuntu/Debian:
sudo ubuntu-drivers autoinstall

# Fedora:
sudo dnf install akmod-nvidia

# Then install DXVK (Vulkan translation layer)
sudo apt install dxvk
```

**Verify:**
```bash
# Test Vulkan:
vulkaninfo | grep "Device Name"

# Should show your GPU (RTX, RX, etc.)
```

---

### Issue: "DLL Loading" Category + Many Warnings

**Diagnosis:**
```
Errors: 12
Estimated Category: DLL Loading Compatibility Issue
```

**Cause:** Complex DLL dependencies, import resolution failing, recursive loading issues.

**Action:**
1. Look at which DLLs loaded successfully
2. Note which didn't
3. Check if missing DLL is a common Windows library or application-specific

```bash
# Re-run with more logging
WINEDEBUG=+loaddll,+imports,+seh wine app.exe 2>&1 | tee debug.log
python3 tools/wine_debug_analyzer.py debug.log
```

---

### Issue: "Threading" Category + "Unhandled exception"

**Diagnosis:**
```
Errors: 3
  [1] Unhandled exception in thread 0024:002c
  [2] Critical section timeout
  [3] Deadlock detected

Estimated Category: Threading Compatibility Issue
```

**Cause:** Wine's threading model doesn't fully match Windows. This is often a race condition.

**Fix:**
```bash
# Try single-threaded mode
WINE_CPU_TOPOLOGY=1:1 wine app.exe

# Or try different scheduler:
WINESERVER_THREAD_POOL=1 wine app.exe
```

---

### Issue: "Networking" Category + "Socket error"

**Diagnosis:**
```
Errors: 2
  [1] Failed to connect to socket: Connection refused
  [2] winsock error

Estimated Category: Networking Compatibility Issue
```

**Cause:** Wine's network configuration needs adjustment.

**Fix:**
```bash
# Try different network driver
# In Wine config:
WINE=wine wine winecfg
# → Staging → CSMT (Compute Shader MultiThreading)
# → Select different driver or disable features

# Or from command line:
wine reg add 'HKEY_CURRENT_USER\Software\Wine\Direct3D' /v CSMT /t REG_SZ /d enabled
```

---

## Step-by-Step Example: Diagnosing Game Crash

Let's say a game crashes immediately after launch.

**Step 1: Static analysis**
```bash
$ python3 tools/pe_inspector.py game.exe | grep -E "Imports|Subsystem"
  Subsystem: GUI
  Imports: kernel32, user32, d3d11, dxgi, opengl32, dsound

Result: Needs DirectX 11 graphics, audio, basic APIs
```

**Step 2: Memory model**
```bash
$ python3 tools/pe_mapper.py game.exe | head -20
  Image base: 0x400000
  Size: 0x2000000  (32 MB)
  Relocations: yes

Result: Game expects 32MB at 0x400000, can rebase if needed
```

**Step 3: Run with debug log**
```bash
$ WINEDEBUG=+loaddll,+seh wine game.exe 2>&1 | tee game-debug.log
$ # Wait 5 seconds, app crashes
$ # Ctrl+C to stop
```

**Step 4: Analyze**
```bash
$ python3 tools/wine_debug_analyzer.py game-debug.log

DLLs Loaded: 25
Missing DLLs: 0
Warnings: 3
  [1] Format WINED3DFMT_R16F not supported by device
  [2] Cannot find Vulkan driver
  [3] Unimplemented feature level 12_1

Errors: 2
  [1] err:d3d11:device_create Failed to create swapchain
  [2] err:dsound:IDirectSound_fnCreateSoundBuffer Failed

First Failure: Line 156 - Failed to create swapchain (DirectX)

Estimated Category: Graphics Compatibility Issue
```

**Conclusion:**
- DLLs loaded fine (no missing dependencies)
- But graphics setup failed
- Vulkan driver not found → Need GPU drivers

**Action:**
```bash
# Install GPU drivers and DXVK
sudo apt install -y dxvk nvidia-driver-XXX  # or amd drivers

# Try again
wine game.exe
```

---

## Using WoadyCompat Tools in Your Workflow

### Quick Compatibility Check

```bash
#!/bin/bash
exe="$1"
echo "=== Quick Compatibility Check ==="
echo ""
echo "1. Binary requirements:"
python3 pe_inspector.py "$exe" | grep -E "Imports|Subsystem|Machine"
echo ""
echo "2. Memory layout:"
python3 pe_mapper.py "$exe" | grep -E "Image base|Total image size|STEP"
```

### Detailed Diagnosis

```bash
#!/bin/bash
exe="$1"
echo "1. Static analysis..."
python3 tools/pe_inspector.py "$exe" > analysis.txt
echo "   → analysis.txt"

echo "2. Loader model..."
python3 tools/pe_mapper.py "$exe" > mapping.txt
echo "   → mapping.txt"

echo "3. Running with debug..."
WINEDEBUG=+loaddll,+seh timeout 10 wine "$exe" 2>&1 | tee debug.log

echo "4. Analyzing failures..."
python3 tools/wine_debug_analyzer.py debug.log > diagnosis.txt
echo "   → diagnosis.txt"

echo ""
echo "Summary:"
grep -E "Missing DLLs|Estimated Category|First Failure" diagnosis.txt
```

---

## Key Takeaways

1. **Start static** — Use PE tools to understand what the binary needs
2. **Model the layout** — Use PE mapper to understand memory expectations  
3. **Run and observe** — Use Wine debug logs to see what actually happens
4. **Analyze systematically** — Use debug analyzer to find the root cause
5. **Fix iteratively** — Address the first failure, test again, repeat

Most compatibility issues fall into clear categories:
- **Graphics** → DXVK/VKD3D + GPU drivers
- **DLL loading** → Missing dependencies, winetricks
- **Threading** → Wine config, scheduler options
- **Networking** → Network driver, winsock config
- **Audio** → PulseAudio/ALSA, DSOUND emulation

---

## References

- **Wine Wiki:** https://wiki.winehq.org/
- **Proton Compatibility:** https://protondb.com/
- **DXVK:** https://github.com/doitsujin/dxvk
- **Winetricks:** https://wiki.winehq.org/Winetricks
- **Debug Channels:** https://wiki.winehq.org/Debug_Channels

