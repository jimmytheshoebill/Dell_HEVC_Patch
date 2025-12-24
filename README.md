# Dell HEVC Hardware Decode Enable Patch

Enable HEVC/H.265 hardware decoding on Dell systems with Intel Arc graphics.

## Problem

Dell systems with Intel Arc GPUs have HEVC hardware decode **artificially disabled** by Intel's DXVA drivers. The driver checks SMBIOS for Dell manufacturer and a feature flag, then masks out HEVC decode capabilities even though the hardware fully supports it.

## Requirements

- **Dell system with Intel Arc graphics** (tested on Latitude Rugged series)
- **Official Intel Arc drivers** from intel.com (Dell OEM drivers not tested)
- **Test Mode enabled** OR **Secure Boot disabled** (required to modify DriverStore files)
- **Administrator privileges**

### Enable Test Mode (if Secure Boot is on)

```cmd
bcdedit /set testsigning on
```
Then reboot. To disable later: `bcdedit /set testsigning off`

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

After patching and rebooting, verify HEVC decode is enabled:

1. Run [DXVA Checker](https://bluesky-soft.com/en/DXVAChecker.html)
2. Look for `HEVC_VLD_Main` and related profiles in the decoder list

## Disclaimer

This patch modifies system driver files. Use at your own risk. The author is not responsible for any system instability or issues that may arise.

## License

MIT License
