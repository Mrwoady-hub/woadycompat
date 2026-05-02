#!/usr/bin/env python3
"""
WoadyCompat SPIR-V Inspector — Phase 5
Static inspector for compiled GPU shader binaries (.spv files).
Same concept as pe_inspector.py but for the shader format DXVK emits.

Safety boundaries:
  - Static analysis only. The shader is never executed or uploaded to a GPU.
  - No Vulkan API calls. No pipeline creation. No device interaction.
  - Uses only Python standard library.
"""

import argparse
import os
import struct
import sys

# ---------------------------------------------------------------------------
# SPIR-V constants (from the SPIR-V specification)
# ---------------------------------------------------------------------------

SPIRV_MAGIC_LE = 0x07230203   # little-endian SPIR-V files
SPIRV_MAGIC_BE = 0x03022307   # big-endian SPIR-V files (rare)

# Version word encodes major/minor: bits 23:16 = major, bits 15:8 = minor
def decode_version(word):
    major = (word >> 16) & 0xFF
    minor = (word >> 8)  & 0xFF
    return major, minor

# Generator magic number registry (partial — top generators)
GENERATORS = {
    0x00070000: "Khronos glslang (GLSL/HLSL compiler)",
    0x00080001: "Khronos SPIRV-Tools assembler",
    0x000D0000: "Google shaderc",
    0x000E0000: "Google spiregg",
    0x000F0000: "Google rspirv",
    0x00100000: "Khronos SPIR-V Tools linker",
    0x000C0000: "LLVM/SPIR-V translator",
    0x00060000: "Khronos SPIR-V for OpenCL",
    0x00020000: "Khronos OpenCL C compiler",
}

# Opcode names for the most common instructions (Op values 0–400 subset)
# Full table: https://registry.khronos.org/SPIR-V/specs/unified1/SPIRV.html
OPCODES = {
    0:   "OpNop",
    1:   "OpUndef",
    2:   "OpSourceContinued",
    3:   "OpSource",
    4:   "OpSourceExtension",
    5:   "OpName",
    6:   "OpMemberName",
    7:   "OpString",
    8:   "OpLine",
    10:  "OpExtension",
    11:  "OpExtInstImport",
    12:  "OpExtInst",
    14:  "OpMemoryModel",
    15:  "OpEntryPoint",
    16:  "OpExecutionMode",
    17:  "OpCapability",
    19:  "OpTypeVoid",
    20:  "OpTypeBool",
    21:  "OpTypeInt",
    22:  "OpTypeFloat",
    23:  "OpTypeVector",
    24:  "OpTypeMatrix",
    25:  "OpTypeImage",
    26:  "OpTypeSampler",
    27:  "OpTypeSampledImage",
    28:  "OpTypeArray",
    29:  "OpTypeRuntimeArray",
    30:  "OpTypeStruct",
    32:  "OpTypePointer",
    33:  "OpTypeFunction",
    41:  "OpConstantTrue",
    42:  "OpConstantFalse",
    43:  "OpConstant",
    44:  "OpConstantComposite",
    46:  "OpConstantNull",
    48:  "OpSpecConstantTrue",
    49:  "OpSpecConstantFalse",
    50:  "OpSpecConstant",
    54:  "OpFunction",
    55:  "OpFunctionParameter",
    56:  "OpFunctionEnd",
    57:  "OpFunctionCall",
    59:  "OpVariable",
    61:  "OpLoad",
    62:  "OpStore",
    65:  "OpAccessChain",
    71:  "OpDecorate",
    72:  "OpMemberDecorate",
    77:  "OpVectorShuffle",
    80:  "OpCompositeConstruct",
    81:  "OpCompositeExtract",
    84:  "OpTranspose",
    87:  "OpSampledImage",
    88:  "OpImageSampleImplicitLod",
    89:  "OpImageSampleExplicitLod",
    124: "OpConvertFToU",
    125: "OpConvertFToS",
    126: "OpConvertSToF",
    127: "OpConvertUToF",
    128: "OpUConvert",
    129: "OpSConvert",
    130: "OpFConvert",
    131: "OpQuantizeToF16",
    133: "OpBitcast",
    139: "OpSNegate",
    140: "OpFNegate",
    141: "OpIAdd",
    142: "OpFAdd",
    143: "OpISub",
    144: "OpFSub",
    145: "OpIMul",
    146: "OpFMul",
    147: "OpUDiv",
    148: "OpSDiv",
    149: "OpFDiv",
    150: "OpUMod",
    151: "OpSRem",
    152: "OpSMod",
    153: "OpFRem",
    154: "OpFMod",
    155: "OpVectorTimesScalar",
    156: "OpMatrixTimesScalar",
    157: "OpVectorTimesMatrix",
    158: "OpMatrixTimesVector",
    159: "OpMatrixTimesMatrix",
    160: "OpOuterProduct",
    161: "OpDot",
    169: "OpShiftRightLogical",
    170: "OpShiftRightArithmetic",
    171: "OpShiftLeftLogical",
    172: "OpBitwiseOr",
    173: "OpBitwiseXor",
    174: "OpBitwiseAnd",
    175: "OpNot",
    189: "OpLogicalEqual",
    190: "OpLogicalNotEqual",
    191: "OpLogicalOr",
    192: "OpLogicalAnd",
    193: "OpLogicalNot",
    194: "OpSelect",
    195: "OpIEqual",
    196: "OpINotEqual",
    197: "OpUGreaterThan",
    198: "OpSGreaterThan",
    199: "OpUGreaterThanEqual",
    200: "OpSGreaterThanEqual",
    201: "OpULessThan",
    202: "OpSLessThan",
    203: "OpULessThanEqual",
    204: "OpSLessThanEqual",
    205: "OpFOrdEqual",
    206: "OpFUnordEqual",
    207: "OpFOrdNotEqual",
    208: "OpFUnordNotEqual",
    213: "OpFOrdLessThan",
    219: "OpFOrdGreaterThan",
    245: "OpPhi",
    246: "OpLoopMerge",
    247: "OpSelectionMerge",
    248: "OpLabel",
    249: "OpBranch",
    250: "OpBranchConditional",
    251: "OpSwitch",
    252: "OpKill",
    253: "OpReturn",
    254: "OpReturnValue",
    255: "OpUnreachable",
}

EXECUTION_MODELS = {
    0: "Vertex",
    1: "TessellationControl",
    2: "TessellationEvaluation",
    3: "Geometry",
    4: "Fragment",
    5: "GLCompute",
    6: "Kernel",
}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def inspect(path: str) -> None:
    # --- Read file ---
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    file_size = len(raw)

    print("=" * 64)
    print("  WoadyCompat SPIR-V Inspector")
    print("=" * 64)
    print(f"  File : {os.path.basename(path)}")
    print(f"  Path : {os.path.abspath(path)}")
    print(f"  Size : {file_size:,} bytes")

    # --- Validate size is a multiple of 4 ---
    if file_size % 4 != 0:
        print(f"\n  ERROR: file size {file_size} is not a multiple of 4 — not a valid SPIR-V binary.")
        sys.exit(1)

    if file_size < 20:
        print("\n  ERROR: file too small to contain a SPIR-V header (minimum 20 bytes).")
        sys.exit(1)

    # --- Detect endianness from magic ---
    magic_raw = struct.unpack_from("<I", raw, 0)[0]

    if magic_raw == SPIRV_MAGIC_LE:
        endian = "<"
        endian_name = "little-endian"
    elif magic_raw == SPIRV_MAGIC_BE:
        endian = ">"
        endian_name = "big-endian"
    else:
        print(f"\n  ERROR: magic {magic_raw:#010x} is not the SPIR-V magic (0x07230203).")
        print("  This file is not a compiled SPIR-V shader.")
        sys.exit(1)

    def word(offset_words):
        return struct.unpack_from(endian + "I", raw, offset_words * 4)[0]

    # --- SPIR-V header (5 words = 20 bytes) ---
    magic      = word(0)
    version_w  = word(1)
    generator  = word(2)
    bound      = word(3)
    schema     = word(4)

    major, minor = decode_version(version_w)
    gen_name = GENERATORS.get(generator & 0xFFFF0000,
               GENERATORS.get(generator, f"Unknown ({generator:#010x})"))

    print()
    print("-" * 64)
    print("  SPIR-V HEADER")
    print("-" * 64)
    print(f"  Magic     : {magic:#010x}  [VALID — {endian_name}]")
    print(f"  Version   : {version_w:#010x}  -> SPIR-V {major}.{minor}")
    print(f"  Generator : {generator:#010x}  -> {gen_name}")
    print(f"  Bound     : {bound}  (IDs 1..{bound - 1} may be used)")
    print(f"  Schema    : {schema}  (reserved, must be 0)")

    total_words = file_size // 4

    # --- Entry points (scan for OpEntryPoint = opcode 15) ---
    entry_points = []
    w = 5
    while w < total_words:
        instr_word = word(w)
        opcode     = instr_word & 0xFFFF
        word_count = (instr_word >> 16) & 0xFFFF
        if word_count == 0:
            break
        if opcode == 15 and w + 2 < total_words:
            exec_model = word(w + 1) & 0xFFFF
            model_name = EXECUTION_MODELS.get(exec_model, f"model#{exec_model}")
            # Name string starts at word w+3, null-terminated within packed words
            name_words = []
            for i in range(w + 3, min(w + word_count, total_words)):
                chunk = word(i).to_bytes(4, byteorder='little' if endian == '<' else 'big')
                name_words.append(chunk)
            name_bytes = b"".join(name_words)
            name = name_bytes.split(b"\x00")[0].decode("utf-8", errors="replace")
            entry_points.append((model_name, name))
        w += word_count

    if entry_points:
        print()
        print("-" * 64)
        print("  ENTRY POINTS")
        print("-" * 64)
        for model, name in entry_points:
            print(f"  Stage: {model:<28}  Name: {name}")

    # --- First 20 instructions ---
    print()
    print("-" * 64)
    print("  FIRST 20 INSTRUCTIONS  (word offset / opcode / name / word-count)")
    print("-" * 64)

    w = 5
    shown = 0
    while w < total_words and shown < 20:
        instr_word = word(w)
        opcode     = instr_word & 0xFFFF
        word_count = (instr_word >> 16) & 0xFFFF

        if word_count == 0:
            print(f"  word {w:>5}: word_count=0 — malformed instruction, stopping.")
            break

        op_name = OPCODES.get(opcode, f"Op???")
        print(f"  word {w:>5}: op={opcode:>5}  {op_name:<32}  words={word_count}")

        w += word_count
        shown += 1

    remaining = 0
    tmp = w
    while tmp < total_words:
        iw = word(tmp)
        wc = (iw >> 16) & 0xFFFF
        if wc == 0:
            break
        remaining += 1
        tmp += wc

    if remaining > 0:
        print(f"  ... and {remaining} more instruction(s) not shown.")

    print()
    print("-" * 64)
    print(f"  Total file words : {total_words}  (header=5, instructions={total_words - 5})")
    print("=" * 64)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="WoadyCompat SPIR-V Inspector: static analysis of compiled GPU shaders.",
        epilog="Safety: read-only static inspection. The shader is never executed or uploaded to a GPU.",
    )
    parser.add_argument(
        "file",
        metavar="FILE",
        help="Path to a compiled SPIR-V binary (.spv)",
    )
    args = parser.parse_args()
    inspect(args.file)


if __name__ == "__main__":
    main()
