Proof-of-concept for [CVE-2025-21479](https://docs.qualcomm.com/product/publicresources/securitybulletin/june-2025-bulletin.html), demonstrating that it only affects Adreno A7xx (Snapdragon 8 Gen 1 / XR2 Gen 2 and newer) devices.

This only tests whether the device is vulnerable - getting this to actually do anything interesting would require more effort.

On unpatched Adreno A7xx devices, running this should print:

```
0 0
```

On Adreno A6xx devices, running this prints:

```
41414141 42424242
```

https://notnow.dev/notice/AvIZRBttG7DsDhx9hw

Patched Adreno A7xx (e.g. Samsung devices after the [2025 May security update](https://security.samsungmobile.com/serviceWeb.smsb)) should also print this, but I have not tested it.

# How to use

```
# adjust path to point to your Android NDK
bash build.sh
adb push cheese /data/local/tmp
adb shell /data/local/tmp/cheese
```

# Thanks

This is based on other researchers' Adreno GPU writeups: this uses code from:
- [Project Zero/Ben Hawkes's Adrenaline](https://googleprojectzero.blogspot.com/2020/09/attacking-qualcomm-adreno-gpu.html)
- [GitHub Security/Man Yue Mo's adreno_user](https://github.blog/security/vulnerability-research/the-code-that-wasnt-there-reading-memory-on-an-android-device-by-accident/)
- [Freedreno/Rob Clark's kilroy](https://github.com/robclark/kilroy/blob/master/kilroy.c)

Additional info on Adreno GPUs' firmware, including how to diff the firmware and how the firmware works, comes from from Freedreno's [afuc documentation](https://gitlab.freedesktop.org/mesa/mesa/-/blob/c0f56fc64cad946d5c4fda509ef3056994c183d9/src/freedreno/afuc/README.rst) by Rob Clark, Connor Abbott, and other Freedreno/Turnip contributors.

Thanks to the [XRBreak community](https://estradiol.city/@ity/114482800282797778) for their support.

# How it works

https://notnow.dev/notice/Av4sfoQjyrxogkZ6Ya

This runs a command buffer on the Adreno GPU (Using a modified version of [Project Zero's Adrenaline code](https://googleprojectzero.blogspot.com/2020/09/attacking-qualcomm-adreno-gpu.html))

Run `CP_SET_MODE` - this enables draw states to run immediately.

Run `CP_SET_DRAW_STATE` - this sets `IB_LEVEL` to 0x4, then calls a instruction buffer.

Inside the `CP_SET_DRAW_STATE`, run `CP_SMMU_TABLE_UPDATE`.

Here’s the firmware handling `CP_SMMU_TABLE_UPDATE`:

```
CP_SMMU_TABLE_UPDATE:
// get IB level
and $02, $12, 0x3
// if not 0 (kernel ring buffer), go to CP_NOP
brne $02, 0x0, #l1873
<actual SMMU modify code >
(IB level = 4) & 0x3 == 0
```

So with IB_LEVEL=4, masking 4 with 3 gives you 0, which passes the check for kernel ring buffer.

So you can change the pagetables and causes the GPU to error out.

# How I diffed the patch

I diffed several Samsung Galaxy firmwares using Freedreno's [afuc](https://gitlab.freedesktop.org/mesa/mesa/-/blob/c0f56fc64cad946d5c4fda509ef3056994c183d9/src/freedreno/afuc/README.rst) disassembler.

The Galaxy S24 firmware was the most helpful, since its GPU firmware only differs by one version - the security fix:

https://notnow.dev/notice/AuueszvUVUQnWqMQeO

https://notnow.dev/notice/Av0kDfOUPKhqHyjyxE

Galaxy S24 firmware: `gen70900_sqe.fw`
- April update (S921USQU4BYD9): v675
- May update (S921USQS4BYE4): v676

https://notnow.dev/notice/Av0a7wUouVSa3EKkE4

Diffing Galaxy S24 Adreno firmware between v675 and v676 shows one type of diff:

```diff
        0163: b80300a4  CP_ME_INIT:
        0163: b80300a4  fxn355:
        0163: b80300a4  cread $03, [$00 + 0x0a4]
-       0164: 2a440003  and $04, $12, 0x3
+       0164: 2a440007  and $04, $12, 0x7
        0165: 98641813  ushr $03, $03, $04
        0166: c860004a  brne $03, b0, #l432
        0167: 01000000  nop
```
Every access to `$12` now ANDs with `0x7` instead of `0x3`. There are no other changes.

https://gist.github.com/zhuowei/46a68b9ee53589cdeaa40c11d15d895f

Register $12 seems to be the IB level:
https://gitlab.freedesktop.org/mesa/mesa/-/blob/c0f56fc64cad946d5c4fda509ef3056994c183d9/src/freedreno/afuc/README.rst#id23
https://gitlab.freedesktop.org/mesa/mesa/-/blob/c0f56fc64cad946d5c4fda509ef3056994c183d9/src/freedreno/afuc/README.rst#id29

Which selects which queue of draw commands will be read.
https://gitlab.freedesktop.org/mesa/mesa/-/blob/c0f56fc64cad946d5c4fda509ef3056994c183d9/src/freedreno/afuc/README.rst#id31

The Adreno 7xx hardware supports 5 queues (RB (kernel ringbuffer, priviledged), IB1, IB2, IB3, or SDS):
https://cs.android.com/android/platform/superproject/main/+/main:external/mesa3d/src/freedreno/registers/adreno/adreno_control_regs.xml;l=327;drc=c0867f48117dc2c18b1ae689235cb1f60b237600

https://notnow.dev/notice/Av0kDfOUPKhqHyjyxE

I think this diff is CVE-2025-21479.
It looks like it only affects Adreno A7xx devices (Snapdragon 8 Gen 1 and above).
Maybe the [Qualcomm bulletin](https://docs.qualcomm.com/product/publicresources/securitybulletin/june-2025-bulletin.html#_cve-2025-21479) is wrong?

- A6xx has 4 IB levels: RB, IB1, IB2, and SDS: SDS=0x3
- A7xx adds IB3: now there are 5 IB levels: RB, IB1, IB2, IB3, and SDS=0x4.
- SDS is now 0x4, so masking with 0x3 would give 0x0.


I'm guessing, on an Adreno A7xx device:
- if you could somehow execute commands at IB level 4 (SDS) with `CP_SET_DRAW_STATE`
- and find a command that checks for IB level = RB (kernel-provided ring buffer), such as `CP_SMMU_TABLE_UPDATE`
- you can trick it into bypassing the check

---

According to the [Project Zero blog post](https://googleprojectzero.blogspot.com/2020/09/attacking-qualcomm-adreno-gpu.html), the `CP_INDIRECT_BUFFER` instruction calls an indirect buffer of control processor instructions, 

When an app wants to use the GPU, the kernel's RB (kernel ring buffer) will contain a `CP_INDIRECT_BUFFER` command that calls a user provided Indirect Buffer- IB1. 
This user buffer can call its own indirect buffers: IB2.
On A7xx, there's also IB3.

Additionally, on both A6xx and A7xx, there's SDS, which isn't entered by indirect buffer, but by `CP_SET_DRAW_STATE`.

https://cs.android.com/android/platform/superproject/+/android15-qpr2-release:external/mesa3d/src/freedreno/decode/cffdec.c;l=3030;drc=0dc791ed57dacf9fe3df694d7f285a8d9f942fa7
https://cs.android.com/android/platform/superproject/+/android15-qpr2-release:external/mesa3d/src/freedreno/decode/cffdec.c;l=2283;drc=0dc791ed57dacf9fe3df694d7f285a8d9f942fa7

A6xx has RB, IB1, IB2, and SDS.
`CP_SET_DRAW_STATE` sets IB level to 0x3: in `a650_sqe.fw.v114` from the Galaxy Fold 3 firmware:
```
mov $03, 0x3
or $12, $12, 0x20
call #fxn1132 // there's a branch delay slot, so this isn't executed yet...
cwrite $03, [$00 + @IB_LEVEL]
```

But A7xx now has RB, IB1, IB2, IB3, or SDS.
`CP_SET_DRAW_STATE` now sets IB level to 0x4:
```
mov $03, 0x4
cwrite $03, [$00 + @IB_LEVEL]
```

0x4 & 0x3 = 0x0. 

https://cs.android.com/android/platform/superproject/main/+/main:external/mesa3d/src/freedreno/registers/adreno/adreno_control_regs.xml;l=327;drc=c0867f48117dc2c18b1ae689235cb1f60b237600

So code checking the current IB level will think SDS (set draw state) is RB (kernel ring buffer), and commands such as `CP_SMMU_TABLE_UPDATE` will allow execution.