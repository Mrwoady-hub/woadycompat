# Phase 5 Validation — Vulkan and SPIR-V

## Vulkan Device Enumeration

`tools/vulkan_info.c` successfully enumerated three Vulkan devices:

- NVIDIA GeForce RTX 5070 — discrete GPU
- AMD Ryzen 7 9800X3D iGPU — RADV integrated GPU
- llvmpipe — CPU software renderer

## SPIR-V Inspection

`tools/spirv_inspect.py` successfully inspected `minimal.spv`:

- File size: 664 bytes
- SPIR-V version: 1.0
- Entry point: `main`
- Shader stage: Vertex
- Instruction words: 161

## Result

Phase 5 confirms that WoadyCompat can inspect both:

- Vulkan runtime device availability
- Static SPIR-V shader metadata

This supports the project goal of studying graphics compatibility layers such as DXVK and VKD3D-Proton at an architecture level.
