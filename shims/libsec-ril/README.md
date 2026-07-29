# libsec-ril shim

Vendor RIL wrapper that loads Samsung's real RIL (`libsec-ril-impl.so`) and
intercepts selected requests. Built as `libsec-ril.so` and installed in place of
the stock library name so `rild` loads the shim first.

## Layout

| File | Role |
|------|------|
| `libsec_ril_smsc_shim.cpp` | All shim logic |
| `Android.bp` | Builds `libsec-ril` (`vendor`, 64-bit) wrapping `libsec-ril-impl.so` |

Related pieces outside this directory:

| Path | Role |
|------|------|
| `../../extract-files.py` | Renames stock blob → `libsec-ril-impl.so`; binary NOPs for UICC enablement |
| `../../init/init.esim_switch.rc` | Bridges `persist.sys.esim_switch` → `vendor.calls.esim_switch` |
| `../../packages/EsimSwitcher` | Settings UI that sets the persist prop and refreshes EID |

## How the wrap works

1. `RIL_Init` `dlopen`s `/vendor/lib64/libsec-ril-impl.so`.
2. A shim `RIL_Env` replaces `OnRequestComplete` so OEM/SIM requests the watcher
   fires can wait for completion.
3. The real function table's `onRequest` pointer is swapped for `shimOnRequest`.
4. A detached pthread (`esimSwitchWatch`) starts and watches
   `vendor.calls.esim_switch`.
5. `RIL_SAP_Init` is forwarded unchanged to the real library.

## Features

### 1. CS SMS — force NULL SMSC

**Problem:** Stock RIL mishandles SMSC for circuit-switched SMS.

**Fix:** For `RIL_REQUEST_SEND_SMS` / `SEND_SMS_EXPECT_MORE` only, replace the
SMSC pointer with `nullptr` and pass the PDU through. IMS / other SMS paths are
not touched.

### 2. tsds2 eSIM slot switch (OEM hook)

Samsung stock uses `ExecuteSlotSwitch` → OEM opcode
`SEC_SIM_LOW_LEVEL_CONTROL` (`0x06001415`) on **`RIL_SOCKET_1`**.

Payload (6 bytes):

```text
15 14 00 06 01 <type>
```

| `<type>` | Meaning |
|----------|---------|
| `0x10` | Switch hybrid slot to eSIM |
| `0x11` | Switch back to physical SIM |
| `0x20` | Post-switch follow-up (stock soft path) |

**Control property:** `vendor.calls.esim_switch` = `1` / `0`  
(bridged from `persist.sys.esim_switch` by `init.esim_switch.rc`)

**Ready signal:** `vendor.calls.esim_ready` = `1` when `ril.simslottype2=1`

**Enable path (`runEsimEnable`):**

1. OEM `0x10` on socket 1.
2. Wait until `ril.simslottype2=1`.
3. OEM `0x20` follow-up.
4. Nudge **phone1 only** (`RIL_SOCKET_2`): `RADIO_POWER` / optional
   `SET_SIM_CARD_POWER`. Do **not** thrash primary-socket radio power — that
   knocks the pSIM offline and races slot status.
5. Latch `vendor.calls.esim_ready=1`.

**Disable path:** OEM `0x11`, clear ready.

**Watcher extras:**

- Re-applies on boot if the persist prop is set.
- Recover path if persist wants eSIM but `simslottype2` flipped back (throttled).
- Breadcrumbs in `vendor.calls.esim_dbg` and logcat tag `sec-ril-shim`.

### 3. Synthetic GetEID (`BF3E`) from EFS

**Problem:** Telephony needs `EuiccCard.mCardId` (EID) for LPA. ES10 GetEID over
the modem can return empty even when the eUICC is present.

**Fix:** When a channel APDU looks like GetEID (`BF3E` + tag `5A`):

1. Read `/efs/FactoryApp/eID` (32 ASCII hex chars).
2. Complete the request locally with:

   ```text
   BF3E125A10<32-hex-EID>   SW=9000
   ```

3. Do not forward that APDU to the modem.

Logged as `geteid-synth` / `APDU-RSP … SYNTH sw=9000`.

### 4. Samsung session-id CLA fixup

**Problem:** AOSP does `cla | channel` for logical-channel APDUs. Samsung
`OPEN_CHANNEL` returns session ids like **101** (not ISO 1..19). That yields
CLA `0xE5` for STORE DATA (`0x80 | 101`) and the card returns **`6986`**.

**Fix:** For `TRANSMIT_APDU_*` with `sessionid > 3`:

```text
cla = cla & ~sessionid
```

Example: `E5` → `80`. Modem `+CGLA` already keys off `sessionid`.

Logged as `APDU-CLA fix` / `apdu-cla-fix`.

Without this, ES10 download (`BF22` / `BF2D` / `BF38` / …) fails even though
the ISD-R channel opens.

### 5. APDU diagnostics

`OPEN_CHANNEL` / `CLOSE_CHANNEL` / `TRANSMIT_APDU_*` are logged with socket id,
channel, CLA/INS, ES10 tag class (`BF22`, `BF31`, …), and response SW. Short
status also goes to `vendor.calls.esim_dbg` for live debugging without full
logcat.

## Properties

| Property | Side | Meaning |
|----------|------|---------|
| `persist.sys.esim_switch` | system | User/app intent (`0`/`1`); written by EsimSwitcher |
| `vendor.calls.esim_switch` | vendor | Shim input (from init bridge) |
| `vendor.calls.esim_ready` | vendor | Shim output: hybrid slot is eUICC |
| `vendor.calls.esim_dbg` | vendor | Last breadcrumb string |
| `ril.simslottype2` | RIL | `1` = slot 2 is eSIM |

Useful SW codes seen during bring-up:

| SW | Meaning in this work |
|----|----------------------|
| `9000` | Success |
| `6986` | Bad CLA (fixed by session CLA strip) |
| `6A80` | Incorrect parameters in ES10 payload |

