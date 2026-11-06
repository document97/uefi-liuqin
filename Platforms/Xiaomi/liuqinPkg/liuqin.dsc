##
#  Copyright (c) 2011 - 2022, ARM Limited. All rights reserved.
#  Copyright (c) 2014, Linaro Limited. All rights reserved.
#  Copyright (c) 2015 - 2020, Intel Corporation. All rights reserved.
#  Copyright (c) 2018, Bingxing Wang. All rights reserved.
#  Copyright (c) Microsoft Corporation.
#  Xiaomi Pad 6 Pro (liuqin) derived from the Nothing Phone (2) (pong) SM8475 package.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
##

################################################################################
#
# Defines Section - statements that will be processed to create a Makefile.
#
################################################################################
[Defines]
  PLATFORM_NAME                  = liuqin
  PLATFORM_GUID                  = 58CB8227-94CC-46C3-991A-574007556732
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/liuqinPkg
  SUPPORTED_ARCHITECTURES        = AARCH64
  BUILD_TARGETS                  = RELEASE|DEBUG
  SKUID_IDENTIFIER               = DEFAULT
  FLASH_DEFINITION               = liuqinPkg/liuqin.fdf
  USE_CUSTOM_DISPLAY_DRIVER      = 0

  #
  # Vendor UEFI modules under Binaries/<BINARIES_DEVICE>. pong carries the SM8475 QcomPkg
  # drivers of the same BSP generation; set liuqin after scripts/import-liuqin-binaries.py
  # has generated Binaries/liuqin from the stock uefi.elf.
  #
  BINARIES_DEVICE                = pong

  #
  # The initrd FAT discovery driver (PongBootMemoryDxe). unixnu passes the value of
  # board.toml [firmware.defines]; a standalone build_uefi.py build takes this default.
  #
!ifndef LIUQIN_INITRD_DISK_ENABLED
  DEFINE LIUQIN_INITRD_DISK_ENABLED = 1
!endif

  #
  # 0 = SM8475
  # 1 = SM8475    (Overclocked)
  # 2 = SM7475-AB
  #
  SOC_TYPE                       = 0

!include PalimaPkg/PalimaPkg.dsc.inc

[PcdsFixedAtBuild]
  #
  # DDR Memory
  #
  gArmTokenSpaceGuid.PcdSystemMemoryBase|0x80000000

  #
  # UEFI Stack
  #
  gArmPlatformTokenSpaceGuid.PcdCPUCoresStackBase|0xA760D000
  gArmPlatformTokenSpaceGuid.PcdCPUCorePrimaryStackSize|0x40000

  #
  # SMBIOS
  #
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemManufacturer|"Xiaomi"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemModel|"Pad 6 Pro"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemRetailModel|"liuqin"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemRetailSku|"Pad_6_Pro_liuqin"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemBoardModel|"Pad 6 Pro"

  #
  # Simple Frame Buffer
  #
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferWidth|1800
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferHeight|2880
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferColorDepth|32

  #
  # Platform PEI
  #
  gQcomPkgTokenSpaceGuid.PcdPlatformType|"LA"

[LibraryClasses]
  # UniXNU boot manager core; DarwinBoot provides the XNU loader protocol.
  UniXNULib|UniXNUPkg/Library/UniXNULib/UniXNULib.inf

  #
  # Memory Libraries
  #
  MemoryMapLib|liuqinPkg/Library/MemoryMapLib/MemoryMapLib.inf

  #
  # QCOM Libraries
  #
  ConfigurationMapLib|liuqinPkg/Library/ConfigurationMapLib/ConfigurationMapLib.inf

[Components]
  UniXNUPkg/Application/UniXNU/UniXNU.inf
  UniXNUPkg/Driver/UniXNUDxe/UniXNUDxe.inf
  DarwinBootPkg/Driver/DarwinBoot.inf
  pongPkg/Drivers/PongBootMemoryDxe/PongBootMemoryDxe.inf

