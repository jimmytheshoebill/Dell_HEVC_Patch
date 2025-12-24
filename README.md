# Dell HEVC Hardware Decode Enable Patch

Enable HEVC/H.265 hardware decoding on Dell systems with Intel Arc graphics.

## Use Case

This patch was created to enable **Omnissa Horizon Client** (formerly VMware Horizon) to use HEVC codec for hardware-accelerated decoding when connecting to NVIDIA vGPU servers. Without this patch, Dell systems fall back to software decoding or H.264, resulting in higher CPU usage and reduced visual quality.

## Problem

Dell systems with Intel Arc GPUs have HEVC hardware decode **artificially disabled** by Intel's DXVA drivers. The driver checks SMBIOS for Dell manufacturer and a feature flag, then masks out HEVC decode capabilities even though the hardware fully supports it.

## ⚠️ Warning

**This patch requires modifying protected system files in the Windows DriverStore. You must understand the implications:**

- **Disabling Secure Boot** is required and weakens system security
- Modifying DriverStore files can cause system instability or boot failures
- Incorrect patching may require driver reinstallation or system recovery
- This patch is unsupported by Dell, Intel, or Microsoft

**Only proceed if you:**
- Understand the risks of modifying system drivers
- Have a system backup or recovery method available
- Accept full responsibility for any consequences

## Requirements

- **Dell system with Intel Arc graphics** (tested on Latitude Rugged series)
- **Official Intel Arc drivers** from intel.com (Dell OEM drivers not tested and may have different code paths)
- **Secure Boot disabled** in BIOS (required to disable driver signature enforcement)
- **Administrator privileges**
- **Knowledge of Windows recovery** in case of issues

### Disable Secure Boot

1. Enter BIOS setup (usually F2 or F12 during boot)
2. Find **Secure Boot** setting and set to **Disabled**
3. Save and exit

### Enable Test Mode (Optional)

After disabling Secure Boot, you can enable Test Mode to bypass driver signature checks:

```cmd
bcdedit /set testsigning on
```
Then reboot. To disable later: `bcdedit /set testsigning off`

**Note:** Test Mode displays a watermark on the desktop. This step may not be required on all systems—try patching without it first.

## Usage

### Step 1: Test Pattern Detection (Recommended)

First, verify the script can find the correct patch location in your driver version:

```powershell
# Run as Administrator
.\patch_hevc.ps1 -TestOnly
```

Expected output:
```
igd11dxva64.dll: Patch needed @ 0x11E584
igd11dxva32.dll: Patch needed @ 0xA6C9C
```

If the script reports "Pattern not found" or "Multiple matches", your driver version may not be compatible.

### Step 2: Apply Patch

```powershell
# Run as Administrator
.\patch_hevc.ps1
```

**The script will:**
1. Detect if running in Normal Mode or Safe Mode
2. In Normal Mode: Enable Safe Mode boot and reboot
3. In Safe Mode: Patch DLLs, disable Safe Mode, prompt for reboot

### To Restore Original DLLs

```powershell
.\patch_hevc.ps1 -Restore
```

## Important Notes

### Multiple Driver Versions

The DriverStore may contain multiple Intel driver versions. The script automatically selects the **most recently installed** version. Verify this matches your active driver:

1. Open Device Manager → Display adapters → Intel Arc
2. Properties → Driver tab → Driver Version
3. Compare with script output

If mismatched, you may need to manually specify the correct driver folder.

### After Driver Updates

Intel driver updates will replace the DLLs. **Re-run the patch after each driver update.**

Use `-TestOnly` first to verify compatibility with the new driver version.

### Backups

Original DLLs are automatically backed up with `.hevc_backup` suffix before patching.

## Technical Details

### What Gets Patched

| DLL | Change | Effect |
|-----|--------|--------|
| igd11dxva64.dll | `JNZ` → `JMP` | Skip Dell HEVC masking (64-bit) |
| igd11dxva32.dll | `JNZ` → `JMP` | Skip Dell HEVC masking (32-bit) |

### Dell Detection Logic (Pseudocode)

```c
if (manufacturer == "Dell Inc.") {
    feature = get_smbios_feature_byte();  // "Feature - X" in Type 11
    if ((feature & 0x01) == 0) {
        // Mask HEVC capabilities
        caps[0x84] &= 0x43FFFFFF;  // Clear HEVC VLD bits
    }
}
```

The patch makes the conditional jump unconditional, always skipping the capability masking code.

### Byte Patterns

The dynamic script searches for these exact instruction sequences:

| Architecture | Pattern (hex) |
|--------------|---------------|
| x64 | `A8 01 75 50 81 A6 84 00 00 00 FF FF FF 43` |
| x86 | `F6 C1 01 75 50 81 A0 84 00 00 00 FF FF FF 43` |

The `75` byte (JNZ) is changed to `EB` (JMP).

## Tested Configuration

- **Driver**: Intel Arc Graphics Driver 32.0.101.6577 (official from intel.com)
- **Hardware**: Dell Latitude Rugged with Intel Arc Graphics
- **OS**: Windows 11

## Verification

After patching and rebooting, verify HEVC decode is enabled using [DXVA Checker](https://bluesky-soft.com/en/DXVAChecker.html):

1. Download and run DXVA Checker
2. Select the **Decoder Device** tab
3. Look for these HEVC profiles in the list:
   - `HEVC_VLD_Main`
   - `HEVC_VLD_Main10`

**If these profiles appear, the patch was successful.** HEVC hardware decoding is now available for applications like Omnissa Horizon Client.

**Note:** GPU-Z and some other tools use legacy D3D9 APIs which may still show HEVC as unavailable. This is cosmetic only—DXVA Checker (D3D11) is the authoritative test.

## Disclaimer

This patch modifies system driver files. Use at your own risk. The author is not responsible for any system instability or issues that may arise.

## License

MIT License
