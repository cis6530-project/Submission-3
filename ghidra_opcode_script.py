#!/usr/bin/env python3
# opcode_extractor.py
# One-file launcher + embedded Ghidra post-script (.csv + .opcode)
# - Run with CPython: batches your directory, spawns analyzeHeadless jobs
# - Inside, we generate a temporary ghidra script with [MOD] comments preserved

import os
import sys
import time
import signal
import shutil
import logging
import argparse
import subprocess
from tqdm import tqdm
from typing import List, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

# =========================
# Config / constants
# =========================
RESULTS_SUBDIR = "results"
GHIDRA_PROJECTS_SUBDIR = "ghidra_projects"
DEFAULT_TIMEOUT_SECONDS = 150

GHIDRA_SCRIPT_FILENAME_FULL   = "__ghidra_opcode_script_full__.py"
GHIDRA_SCRIPT_FILENAME_OPCODE = "__ghidra_opcode_script_opcode__.py"

# Where to record hard cases that exceed opcode-only retry
CHECK_MANUALLY_FILENAME = "check_manually.txt"

# [MOD] If you want the Ghidra side to include all memory blocks by default,
#       flip this to True. (This is injected into the generated Ghidra script.)
INCLUDE_ALL_BLOCKS_DEFAULT = False

# [MOD] Global default for number of parallel workers
# Set to 1 for safety; increase slowly if your VM has enough cores/RAM.
DEFAULT_WORKERS = 1

# For the FULL pass, we can require both csv and opcode; SKIP logic elsewhere only needs opcode
REQUIRE_BOTH_OUTPUTS = True

# Retry policy: if full attempt times out, run an opcode-only pass
ENABLE_OPCODE_ONLY_RETRY = True
# Keep this tight so you don't wait forever on the fallback
OPCODE_ONLY_TIMEOUT_SECONDS = 500

# Optional in-script instruction caps (0 = unlimited)
FULL_MAX_INSTR   = 0
OPONLY_MAX_INSTR = 0

# =========================
# Embedded Ghidra post-script (runs in Ghidra's Jython)
# Includes watchdog + optional instruction cap
# =========================
GHIDRA_SCRIPT_CONTENT = r'''
# -*- coding: utf-8 -*-
#@category Export
#@menupath Tools.Export Opcodes (CSV + .opcode)
"""
Headless-safe script:
 - When OPCODES_ONLY=False: stream CSV (addr,bytes_hex,mnemonic,operands,section_name) + .opcode
 - When OPCODES_ONLY=True:  stream only .opcode (mnemonics) and skip bytes/operands (faster)
 - Enforces a time budget (BUDGET_SECONDS) and optional MAX_INSTR cap.
"""

import os
import csv
import logging

from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from java.lang import System

# ---------- Toggles injected from launcher ----------
INCLUDE_ALL_BLOCKS = {INCLUDE_ALL_BLOCKS_BOOL}
OPCODES_ONLY       = {OPCODES_ONLY_BOOL}
BUDGET_SECONDS     = {BUDGET_SECONDS}
MAX_INSTR          = {MAX_INSTR}

# ---------- Arg handling ----------
argv = getScriptArgs()

def _ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def configure_logger(output_folder):
    log_path = os.path.join(output_folder, "extraction.log")
    lg = logging.getLogger("ghidra_export_opcodes")
    lg.setLevel(logging.INFO)
    for h in list(lg.handlers):
        lg.removeHandler(h)
    fh = logging.FileHandler(log_path)
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    lg.addHandler(fh)
    return lg

# Get output / results folders
if len(argv) == 0:
    d = askDirectory("Choose output directory for opcode export", "Select")
    if d is None:
        print("Cancelled by user.")
        exit()
    output_root = d.getAbsolutePath()
    results_folder = os.path.join(output_root, "results")
elif len(argv) == 1:
    output_root = argv[0]
    results_folder = os.path.join(output_root, "results")
elif len(argv) == 2:
    output_root = argv[0]
    results_folder = argv[1]
else:
    printerr("Invalid arguments (0,1 or 2 expected).")
    exit()

_ensure_dir(output_root)
_ensure_dir(results_folder)
logger = configure_logger(output_root)

program_name = currentProgram.getName()
subdir = program_name[:2] if len(program_name) >= 2 else "_"
program_folder = os.path.join(results_folder, subdir)
_ensure_dir(program_folder)

csv_path = os.path.join(program_folder, program_name + ".csv")
opcode_path = os.path.join(program_folder, program_name + ".opcode")

# Main extraction (streaming)
try:
    start_ns = System.nanoTime()
    budget_ns = int(BUDGET_SECONDS * 1.0e9)

    def time_exceeded():
        return (System.nanoTime() - start_ns) >= budget_ns

    memory_blocks = currentProgram.getMemory().getBlocks()
    if (memory_blocks is None) or (len(memory_blocks) == 0):
        msg = "{}: No memory blocks found - file may be packed/damaged".format(program_name)
        logger.error(msg); printerr(msg); exit()

    cf = None
    writer = None
    if not OPCODES_ONLY:
        cf = open(csv_path, "w")
        writer = csv.writer(cf)
        writer.writerow(["addr", "bytes_hex", "mnemonic", "operands", "section_name"])
    of = open(opcode_path, "w")

    total = 0
    flush_every = 50000  # tune if you like
    stop_all = False

    for block in memory_blocks:
        if stop_all:
            break
        if block is None:
            continue
        if (not INCLUDE_ALL_BLOCKS) and (not block.isExecute()):
            continue

        if time_exceeded():
            logger.warning("{}: Budget exceeded before block '{}'".format(program_name, block.getName()))
            stop_all = True
            break

        section_name = block.getName()
        addr_set = AddressSet(block.getStart(), block.getEnd())
        try:
            DisassembleCommand(addr_set, addr_set, True).applyTo(currentProgram)
        except Exception as e:
            logger.warning("{}: DisassembleCommand failed for block {}: {}".format(program_name, section_name, e))

        it = currentProgram.getListing().getInstructions(addr_set, True)
        while it.hasNext():
            if time_exceeded():
                logger.warning("{}: Budget exceeded during block '{}'".format(program_name, section_name))
                stop_all = True
                break
            if (MAX_INSTR > 0) and (total >= MAX_INSTR):
                logger.warning("{}: MAX_INSTR {} reached".format(program_name, MAX_INSTR))
                stop_all = True
                break

            try:
                instr = it.next()
                mnemonic = instr.getMnemonicString() or ""
                of.write(mnemonic + "\n")
                total += 1

                if (total % flush_every) == 0:
                    of.flush()
                    if writer:
                        cf.flush()

                if writer:
                    addr_str = str(instr.getAddress())
                    try:
                        b = instr.getBytes()
                        bytes_hex = "".join("{:02X}".format((bb & 0xFF)) for bb in b)
                    except Exception:
                        bytes_hex = ""
                    try:
                        oplist = instr.getDefaultOperandRepresentationList()
                        operands = ", ".join(str(x) for x in oplist) if oplist else ""
                    except Exception:
                        try:
                            operands = instr.getDefaultOperandRepresentation(0) or ""
                        except Exception:
                            operands = ""
                    writer.writerow([addr_str, bytes_hex, mnemonic, operands, section_name])

            except Exception as ie:
                logger.warning("{}: skipping instruction due to: {}".format(program_name, ie))

    if cf: cf.close()
    of.close()

    elapsed = (System.nanoTime() - start_ns) / 1.0e9
    logger.info("{}: Exported {} instructions in {:.2f}s (INCLUDE_ALL_BLOCKS={}, OPCODES_ONLY={}, budget={}s)".format(
        program_name, total, elapsed, INCLUDE_ALL_BLOCKS, OPCODES_ONLY, BUDGET_SECONDS))
    print("Wrote:")
    if not OPCODES_ONLY: print("  {}".format(csv_path))
    print("  {}".format(opcode_path))
    with open(os.path.join(output_root, "timing.log"), "a") as tf:
        tf.write("{},{:.2f}\n".format(program_name, elapsed))

except Exception as e:
    logger.error("{}: An error occurred while extracting opcodes - {}".format(program_name, e), exc_info=True)
    printerr("{}: An error occurred while extracting opcodes - {}".format(program_name, e))
'''

# =========================
# Launcher (CPython)
# =========================

def configure_logging(output_dir: str) -> logging.Logger:
    extraction_log_file = os.path.join(output_dir, 'extraction.log')
    print(f"Logging to: {extraction_log_file}")
    extraction_logger = logging.getLogger('extraction_logger')
    extraction_logger.setLevel(logging.INFO)
    extraction_logger.handlers.clear()
    extraction_handler = logging.FileHandler(extraction_log_file)
    extraction_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    extraction_logger.addHandler(extraction_handler)
    return extraction_logger

def write_temp_ghidra_script(
    script_dir: str,
    include_all: bool,
    opcodes_only: bool,
    filename: str,
    budget_seconds: int,
    max_instr: int
) -> str:
    """
    Write the embedded Ghidra script into script_dir with toggles and watchdog.
    """
    path = os.path.join(script_dir, filename)
    escaped = GHIDRA_SCRIPT_CONTENT.replace('{', '{{').replace('}', '}}')
    # Re-inject placeholders we actually want to format:
    escaped = escaped.replace('{{INCLUDE_ALL_BLOCKS_BOOL}}', '{INCLUDE_ALL_BLOCKS_BOOL}')
    escaped = escaped.replace('{{OPCODES_ONLY_BOOL}}', '{OPCODES_ONLY_BOOL}')
    escaped = escaped.replace('{{BUDGET_SECONDS}}', '{BUDGET_SECONDS}')
    escaped = escaped.replace('{{MAX_INSTR}}', '{MAX_INSTR}')
    content = escaped.format(
        INCLUDE_ALL_BLOCKS_BOOL=str(include_all),
        OPCODES_ONLY_BOOL=str(opcodes_only),
        BUDGET_SECONDS=str(int(budget_seconds)),
        MAX_INSTR=str(int(max_instr)),
    )
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    return path

def _append_check_manually(output_dir: str, file_name: str, reason: str) -> None:
    try:
        with open(os.path.join(output_dir, CHECK_MANUALLY_FILENAME), "a", encoding="utf-8") as fh:
            fh.write(f"{file_name} :: {reason}\n")
    except Exception:
        pass

def extract_features(
    input_file_path: str,
    output_dir: str,
    ghidra_headless_path: str,
    timeout_seconds: int,
    extraction_logger: logging.Logger,
    script_full_path: str,
    script_oponly_path: str,
    require_both: bool
) -> bool:
    """
    Run Ghidra headless on one file.
    If the full pass times out, retry opcode-only.
    Uses a Python-enforced timeout that kills the entire process group.
    """
    file_name = os.path.basename(input_file_path)
    safe_proj = f"{file_name}_project"
    project_folder = os.path.join(output_dir, GHIDRA_PROJECTS_SUBDIR, safe_proj)
    results_folder = os.path.join(output_dir, RESULTS_SUBDIR)
    os.makedirs(project_folder, exist_ok=True)

    def _timed_out(cp: subprocess.CompletedProcess) -> bool:
        if cp.returncode == 124:
            return True
        if cp.returncode in (137, 143):  # SIGKILL / SIGTERM
            return True
        if cp.returncode is not None and cp.returncode < 0:
            return True
        if (cp.stderr and "timed out" in cp.stderr.lower()) or (cp.stdout and "timed out" in cp.stdout.lower()):
            return True
        return False

    def _run(script_path: str, per_attempt_timeout: int) -> subprocess.CompletedProcess:
        cmd = [
            ghidra_headless_path, project_folder, safe_proj,
            '-import', input_file_path,
            '-noanalysis',
            '-scriptPath', os.path.dirname(script_path),
            '-postScript', os.path.basename(script_path),
            output_dir, results_folder
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid,  # new process group
        )
        try:
            stdout, stderr = proc.communicate(timeout=per_attempt_timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    stdout, stderr = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    stdout, stderr = proc.communicate()
            except ProcessLookupError:
                stdout, stderr = ("", "")
            rc = 124  # mimic timeout
        return subprocess.CompletedProcess(cmd, rc, stdout, stderr)

    try:
        extraction_logger.info(f"{file_name} (timeout={timeout_seconds}s)")
        extraction_logger.info(f"{file_name}: FULL pass (timeout={timeout_seconds}s)")
        result = _run(script_full_path, timeout_seconds)

        # FULL timed out? Retry opcode-only
        if _timed_out(result) and ENABLE_OPCODE_ONLY_RETRY:
            extraction_logger.error(f"{file_name}: Timed out after {timeout_seconds}s (full). Retrying opcode-only...")
            shutil.rmtree(project_folder, ignore_errors=True)
            os.makedirs(project_folder, exist_ok=True)

            extraction_logger.info(f"{file_name}: OPCODE-ONLY pass (timeout={OPCODE_ONLY_TIMEOUT_SECONDS}s)")
            result2 = _run(script_oponly_path, OPCODE_ONLY_TIMEOUT_SECONDS)
            if _timed_out(result2):
                extraction_logger.error(f"{file_name}: Opcode-only retry also timed out after {OPCODE_ONLY_TIMEOUT_SECONDS}s")
                _append_check_manually(output_dir, file_name, f"opcode-only timeout {OPCODE_ONLY_TIMEOUT_SECONDS}s")
                return False
            if result2.returncode != 0:
                extraction_logger.error(f"{file_name}: Opcode-only retry failed (exit {result2.returncode})")
                if result2.stderr:
                    extraction_logger.error(f"{file_name}: {result2.stderr}")
                _append_check_manually(output_dir, file_name, f"opcode-only failed exit {result2.returncode}")
                return False

            # On retry we only require .opcode
            subdir = file_name[:2] if len(file_name) >= 2 else "_"
            opcode_file_path = os.path.join(results_folder, subdir, f"{file_name}.opcode")
            if os.path.exists(opcode_file_path):
                extraction_logger.info(f"{file_name}: Successfully extracted opcode on retry (opcode-only)")
                return True

            extraction_logger.error(f"{file_name}: Opcode-only retry produced no .opcode output")
            _append_check_manually(output_dir, file_name, "opcode-only produced no output")
            return False

        # Non-timeout failure on full attempt
        if result.returncode != 0:
            extraction_logger.error(f"{file_name}: Ghidra analysis failed (exit {result.returncode})")
            if result.stderr:
                extraction_logger.error(f"{file_name}: {result.stderr}")
            _append_check_manually(output_dir, file_name, f"full pass failed exit {result.returncode}")
            return False

        # Verify outputs for the full pass
        subdir = file_name[:2] if len(file_name) >= 2 else "_"
        csv_file_path = os.path.join(results_folder, subdir, f"{file_name}.csv")
        opcode_file_path = os.path.join(results_folder, subdir, f"{file_name}.opcode")

        ok = (os.path.exists(csv_file_path) and os.path.exists(opcode_file_path)) if require_both \
             else (os.path.exists(csv_file_path) or os.path.exists(opcode_file_path))
        if not ok:
            extraction_logger.error(f"{file_name}: Missing expected outputs after full run")
            _append_check_manually(output_dir, file_name, "full run missing outputs")
        return ok

    except Exception as e:
        extraction_logger.error(f"{file_name}: Unexpected error - {e}")
        _append_check_manually(output_dir, file_name, f"exception {e}")
        return False
    finally:
        if os.path.exists(project_folder):
            shutil.rmtree(project_folder, ignore_errors=True)

def extraction(
    input_file_path: str,
    output_marker_path: str,
    file_name: str,
    extraction_logger: logging.Logger,
    output_dir: str,
    ghidra_headless_path: str,
    timeout_seconds: int,
    script_full_path: str,
    script_oponly_path: str,
    require_both: bool
) -> float:
    """
    Per-file wrapper for pool execution.
    SKIP if an .opcode already exists (no need to re-run).
    """
    subdir = file_name[:2] if len(file_name) >= 2 else "_"
    results_folder = os.path.join(output_dir, RESULTS_SUBDIR)
    opcode_path = os.path.join(results_folder, subdir, f"{file_name}.opcode")

    if os.path.exists(opcode_path):
        extraction_logger.info(f"SKIP: {file_name} (already have: opcode)")
        return 0.0

    os.makedirs(os.path.join(results_folder, subdir), exist_ok=True)

    start_time = time.time()
    success = extract_features(
        input_file_path, output_dir, ghidra_headless_path,
        timeout_seconds, extraction_logger,
        script_full_path, script_oponly_path, require_both
    )
    return (time.time() - start_time) if success else 0.0

def get_args(
    binary_path: str,
    output_path: str,
    extraction_logger: logging.Logger,
    ghidra_headless_path: str,
    timeout_seconds: int,
    script_full_path: str,
    script_oponly_path: str,
    require_both: bool
) -> List[Tuple]:
    """
    Build parallel job list. Includes common native binaries + bytecode.
    Skips known-bad/noisy types. Includes extension-less files.
    """
    GOOD_EXTS = {
        '.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl',
        '.so',
        '.dylib',
        '.o',
        '.class', '.dex', '.apk', '.jar', '.war', '.ear',
        '.bin'
    }
    BAD_EXTS = {
        '.dex', '.url', '.inf', '.ps1', '.vbs', '.js', '.macho', '.dmg', '.one', '.swf'
    }

    args = []
    for root, _, files in os.walk(binary_path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()

            if ext in BAD_EXTS:
                continue
            if not (ext in GOOD_EXTS or ext == ''):
                continue

            binary_file_path = os.path.join(root, file)
            subdir = (file[:2] if len(file) >= 2 else "_")
            out_dir_path = os.path.normpath(os.path.join(output_path, RESULTS_SUBDIR, subdir))
            os.makedirs(out_dir_path, exist_ok=True)
            output_marker_path = os.path.join(out_dir_path, f"{file}.csv")  # not used for skip anymore
            args.append((
                binary_file_path, output_marker_path, file, extraction_logger,
                output_path, ghidra_headless_path, timeout_seconds, script_full_path, script_oponly_path, require_both
            ))
    return args

def parallel_process(args: List[Tuple]) -> None:
    """
    Process extraction tasks in parallel.
    """
    max_workers = min(DEFAULT_WORKERS, len(args))
    if max_workers == 0:
        return
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(extraction, *arg) for arg in args]
        with tqdm(total=len(futures), desc="Processing files", unit="file") as pbar:
            for _ in as_completed(futures):
                pbar.update(1)

def setup_output_directory(input_dir: str, custom_output_dir: str = None) -> str:
    """
    Prepare output directories.
    """
    output_dir = custom_output_dir or os.path.join(os.path.dirname(input_dir), f"{os.path.basename(input_dir)}_disassemble")
    print(f"Output directory: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, RESULTS_SUBDIR), exist_ok=True)
    os.makedirs(os.path.join(output_dir, GHIDRA_PROJECTS_SUBDIR), exist_ok=True)
    return output_dir

def parse_arguments() -> argparse.Namespace:
    """
    CLI arguments (launcher side).
    """
    p = argparse.ArgumentParser(description='Batch opcode extraction via Ghidra headless (CSV + .opcode).')
    p.add_argument('-d', '--directory', required=True, help='Path to the binary directory')
    p.add_argument('-g', '--ghidra', required=True, help='Path to Ghidra headless (analyzeHeadless)')
    p.add_argument('-o', '--output', help='Output directory (default: <input_dir>_disassemble)')
    p.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT_SECONDS,
                   help=f'Timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})')
    p.add_argument('--include-all', action='store_true', help='Include ALL memory blocks (overrides script default)')
    return p.parse_args()

def main():
    # SAFETY: run in isolated VM, offline; never execute samples; export only artifacts.
    args = parse_arguments()

    if not os.path.exists(args.ghidra):
        print(f"Error: Ghidra headless analyzer not found at {args.ghidra}")
        sys.exit(2)

    input_dir = os.path.normpath(os.path.expanduser(args.directory))
    output_dir = setup_output_directory(input_dir, args.output)
    extraction_logger = configure_logging(output_dir)

    # Prepare temp Ghidra script directory
    script_dir = os.path.join(output_dir, "_ghidra_scripts")
    os.makedirs(script_dir, exist_ok=True)

    include_all = args.include_all or INCLUDE_ALL_BLOCKS_DEFAULT

    # Budgets: make the in-script budget slightly smaller than the outer timeout
    full_outer   = max(1, int(args.timeout))
    full_budget  = max(1, full_outer - 15)

    # Keep opcode-only retry tight
    oponly_outer  = min(OPCODE_ONLY_TIMEOUT_SECONDS, full_outer)
    oponly_budget = max(1, oponly_outer - 15)

    # --- Write both Ghidra post-scripts (with watchdog + caps) ---
    ghidra_script_full = write_temp_ghidra_script(
        script_dir, include_all, opcodes_only=False,
        filename=GHIDRA_SCRIPT_FILENAME_FULL,
        budget_seconds=full_budget,
        max_instr=FULL_MAX_INSTR
    )
    ghidra_script_opcode = write_temp_ghidra_script(
        script_dir, include_all, opcodes_only=True,
        filename=GHIDRA_SCRIPT_FILENAME_OPCODE,
        budget_seconds=oponly_budget,
        max_instr=OPONLY_MAX_INSTR
    )

    # --- Build per-file job list ---
    jobs = get_args(
        input_dir,
        output_dir,
        extraction_logger,
        args.ghidra,
        full_outer,
        ghidra_script_full,
        ghidra_script_opcode,
        REQUIRE_BOTH_OUTPUTS
    )

    if not jobs:
        print("No candidate files found for extraction.")
        print("Tip: verify file extensions or adjust GOOD_EXTS in get_args().")
        return

    # --- Run extraction in parallel (or sequential if DEFAULT_WORKERS=1) ---
    parallel_process(jobs)

    # Optional cleanup: remove temporary Ghidra project folders
    ghidra_projects_dir = os.path.join(output_dir, GHIDRA_PROJECTS_SUBDIR)
    if os.path.exists(ghidra_projects_dir):
        shutil.rmtree(ghidra_projects_dir, ignore_errors=True)

    print("\nAll extractions complete.")
    print(f"Results saved under: {os.path.join(output_dir, RESULTS_SUBDIR)}")
    cm = os.path.join(output_dir, CHECK_MANUALLY_FILENAME)
    if os.path.exists(cm):
        print(f"Some files need manual checking. See: {cm}")

if __name__ == "__main__":
    main()

