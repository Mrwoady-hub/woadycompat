# Phase 5 — DXVK and Vulkan Architecture Notes

## Goal

Understand how DirectX-to-Vulkan compatibility layers work at a high level without implementing game compatibility, anti-cheat bypasses, DRM bypasses, or executable translation.

## Where DXVK Fits

DXVK acts as a translation layer between Direct3D applications and Vulkan-capable Linux graphics drivers.

```text
Direct3D Application
        ↓
DXVK Direct3D/DXGI layer
        ↓
Vulkan API calls
        ↓
Vulkan ICD / GPU driver
        ↓
GPU hardware
