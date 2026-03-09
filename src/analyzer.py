import os
import re
import sys
import logging
import subprocess
import requests
from pathlib import Path
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# Set GHIDRA_INSTALL_DIR if not present, based on our prior discovery
# This helps ensure pyghidra finds the installation automatically
if "GHIDRA_INSTALL_DIR" not in os.environ:
    # Found during reconnaissance
    os.environ["GHIDRA_INSTALL_DIR"] = "/home/jogo/Desktop/Ghidra/ghidra_12.0_PUBLIC"

try:
    import pyghidra
    from pyghidra.core import FlatProgramAPI
except ImportError:
    # Fallback/Mock for environments where pyghidra might fail to load (e.g. no Java)
    # This keeps the code importable for checking structure
    pass

class GhidraAnalyzer:
    """
    Handles interaction with Ghidra via PyGhidra to analyze binaries
    and extract decompiled code.
    """
    
    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path).resolve()
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")
        
        # Verify pyghidra availability
        if "pyghidra" not in sys.modules:
             try:
                 import pyghidra
             except ImportError:
                 raise ImportError("pyghidra is not installed or configured correctly.")

    def decompile(self, function_name: Optional[str] = None) -> Dict[str, str]:
        """
        Analyzes the binary and returns decompiled code.
        
        Args:
            function_name: Optional name of specific function to decompile.
                           If None, decompiles 'main' or the entry point.
                           
        Returns:
            Dictionary mapping function names to decompiled source code.
        """
        results = {}
        
        # We use the open_program context manager from pyghidra
        # This acts as a headless analyzer
        from pyghidra import open_program
        
        with open_program(str(self.binary_path), analyze=True) as flat_api:
            # flat_api is an instance roughly equivalent to Ghidra's FlatProgramAPI
            # plus some pyghidra conveniences
            
            program = flat_api.getCurrentProgram()
            listing = program.getListing()
            decomp_interface = self._setup_decompiler(flat_api)
            
            # Find target function(s)
            funcs_to_process = []
            
            if function_name:
                # Find specific function
                # getGlobalFunctions returns a list
                funcs = flat_api.getGlobalFunctions(function_name)
                if not funcs:
                     # Try to find by symbol if global function lookup fails
                     syms = flat_api.getSymbolAt_as_list(function_name) 
                     # This logic can be complex in Ghidra; keeping it simple for now
                     # Revert to iterating if needed or assume user provides exact name
                     pass
                funcs_to_process.extend(funcs)
            else:
                # Decompile all non-external functions
                func_iter = listing.getFunctions(True)
                for f in func_iter:
                    if not f.isExternal():
                        funcs_to_process.append(f)
            
            # Decompile
            monitor = flat_api.getMonitor()
            for func in funcs_to_process:
                if func is None:
                    continue
                
                name = func.getName()
                print(f"Decompiling {name}...")
                
                decomp_res = decomp_interface.decompileFunction(func, 0, monitor)
                if decomp_res.decompileCompleted():
                    c_code = decomp_res.getDecompiledFunction().getC()
                    results[name] = c_code
                else:
                    results[name] = f"// Decompilation failed for {name}"
                    
        return results

    def analyze_security(self, decompiled_functions: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Performs a comprehensive security check on the binary.
        Checks for:
        - Dangerous functions (Ghidra symbol table)
        - Security mitigations: NX, Canary, PIE, RELRO, Fortify Source
        - Vulnerable call sites (cross-ref with decompiled code)
        - Known CVEs for linked libraries
        """
        results = {
            "flaws": [],
            "mitigations": {
                "Canary": False,
                "NX": True,  # Assume True until proven False
                "PIE": "Unknown",
                "RELRO": "Unknown",
                "Fortify": False
            },
            "vulnerable_call_sites": [],
            "known_cves": [],
            "fortified_functions": [],
            "linked_libraries": []
        }
        
        dangerous_funcs = ["gets", "strcpy", "strcat", "sprintf", "system", 
                           "execve", "popen", "mktemp", "scanf", "vsprintf",
                           "realpath", "getwd"]
        
        # ── Phase 1: Ghidra-based analysis (Canary, NX, Dangerous Imports) ──
        from pyghidra import open_program
        
        with open_program(str(self.binary_path), analyze=True) as flat_api:
            program = flat_api.getCurrentProgram()
            symbol_table = program.getSymbolTable()
            
            # 1a. Check for dangerous functions
            for func_name in dangerous_funcs:
                syms = symbol_table.getGlobalSymbols(func_name)
                if syms:
                    results["flaws"].append(f"Uses dangerous function: {func_name}")
            
            # 1b. Check for Stack Canary
            chk_fail = symbol_table.getGlobalSymbols("__stack_chk_fail")
            if chk_fail:
                results["mitigations"]["Canary"] = True
            
            # 1c. Check for NX (No-Execute)
            memory = program.getMemory()
            blocks = memory.getBlocks()
            for block in blocks:
                if block.isExecute() and block.isWrite():
                    results["mitigations"]["NX"] = False
                    results["flaws"].append(f"Memory block {block.getName()} is W+X (Writable and Executable)")
            
            # 1d. Fortify Source: look for __*_chk function imports
            fortified_funcs = [
                "__memcpy_chk", "__memmove_chk", "__memset_chk",
                "__strcpy_chk", "__strncpy_chk", "__strcat_chk", "__strncat_chk",
                "__sprintf_chk", "__snprintf_chk", "__vsprintf_chk", "__vsnprintf_chk",
                "__printf_chk", "__fprintf_chk", "__vfprintf_chk",
                "__read_chk", "__gets_chk", "__fgets_chk",
                "__realpath_chk", "__getwd_chk"
            ]
            found_fortified = []
            for func_name in fortified_funcs:
                syms = symbol_table.getGlobalSymbols(func_name)
                if syms:
                    found_fortified.append(func_name)
            
            if found_fortified:
                results["mitigations"]["Fortify"] = True
                results["fortified_functions"] = found_fortified
        
        # ── Phase 2: ELF header analysis (PIE, RELRO) via pyelftools ──
        try:
            self._analyze_elf_headers(results)
        except Exception as e:
            logger.warning(f"ELF header analysis failed: {e}")
        
        # ── Phase 3: Vulnerable call site tracking ──
        if decompiled_functions:
            try:
                self._find_vulnerable_call_sites(results, decompiled_functions, dangerous_funcs)
            except Exception as e:
                logger.warning(f"Call site tracking failed: {e}")
        
        # ── Phase 4: CVE matching for linked libraries ──
        try:
            self._check_cves(results)
        except Exception as e:
            logger.warning(f"CVE matching failed: {e}")
            
        return results
    
    def _analyze_elf_headers(self, results: Dict[str, Any]):
        """
        Analyzes ELF headers using pyelftools for PIE and RELRO detection.
        """
        from elftools.elf.elffile import ELFFile
        
        with open(str(self.binary_path), 'rb') as f:
            try:
                elf = ELFFile(f)
            except Exception:
                logger.warning("File is not a valid ELF binary, skipping ELF analysis.")
                return
            
            # ── PIE Detection ──
            e_type = elf.header['e_type']
            if e_type == 'ET_DYN':
                results["mitigations"]["PIE"] = True
            elif e_type == 'ET_EXEC':
                results["mitigations"]["PIE"] = False
                results["flaws"].append("Binary is not Position-Independent (no PIE). ASLR cannot randomize the base address.")
            
            # ── RELRO Detection ──
            has_relro_segment = False
            has_bind_now = False
            
            for segment in elf.iter_segments():
                if segment.header['p_type'] == 'PT_GNU_RELRO':
                    has_relro_segment = True
            
            # Check .dynamic section for BIND_NOW
            dynamic = elf.get_section_by_name('.dynamic')
            if dynamic:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == 'DT_BIND_NOW':
                        has_bind_now = True
                    if tag.entry.d_tag == 'DT_FLAGS' and (tag.entry.d_val & 0x8):  # DF_BIND_NOW
                        has_bind_now = True
                    if tag.entry.d_tag == 'DT_FLAGS_1' and (tag.entry.d_val & 0x1):  # DF_1_NOW
                        has_bind_now = True
            
            if has_relro_segment and has_bind_now:
                results["mitigations"]["RELRO"] = "Full"
            elif has_relro_segment:
                results["mitigations"]["RELRO"] = "Partial"
                results["flaws"].append("Only Partial RELRO: GOT is still writable after startup (vulnerable to GOT overwrite attacks).")
            else:
                results["mitigations"]["RELRO"] = False
                results["flaws"].append("No RELRO: GOT and other relocations are fully writable (vulnerable to GOT overwrite attacks).")
            
            # ── Extract linked libraries for CVE check ──
            linked_libs = []
            if dynamic:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        linked_libs.append(tag.needed)
            results["linked_libraries"] = linked_libs
    
    def _find_vulnerable_call_sites(self, results: Dict[str, Any], 
                                     decompiled_functions: Dict[str, str],
                                     dangerous_funcs: List[str]):
        """
        Scans decompiled C code for exact locations of dangerous function calls.
        """
        vulnerable_sites = []
        
        for func_name, code in decompiled_functions.items():
            if not code or code.startswith("// Decompilation failed"):
                continue
            
            lines = code.split('\n')
            for dangerous in dangerous_funcs:
                # Match function calls like: gets(buf), strcpy(dst, src)
                pattern = rf'\b{re.escape(dangerous)}\s*\('
                for line_num, line in enumerate(lines, start=1):
                    if re.search(pattern, line):
                        vulnerable_sites.append({
                            "function": func_name,
                            "dangerous_call": dangerous,
                            "line": line_num,
                            "context": line.strip()
                        })
        
        results["vulnerable_call_sites"] = vulnerable_sites
        
        # Also add summary flaws for call sites
        if vulnerable_sites:
            unique_calls = set(s["dangerous_call"] for s in vulnerable_sites)
            for call in unique_calls:
                sites = [s for s in vulnerable_sites if s["dangerous_call"] == call]
                funcs = list(set(s["function"] for s in sites))
                results["flaws"].append(
                    f"Dangerous call '{call}()' found in: {', '.join(funcs)}"
                )
    
    def _check_single_lib_cves(self, lib: str) -> List[Dict[str, Any]]:
        """Check CVEs for a single library. Used for parallel execution."""
        lib_base = lib.split('.so')[0] if '.so' in lib else lib
        cves = []
        
        try:
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "keywordSearch": lib_base,
                    "resultsPerPage": 3
                },
                timeout=5  # Reduced from 10s for faster failure
            )
            
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "Unknown")
                    
                    # Get description
                    desc = "No description available."
                    for d in cve_data.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", desc)
                            break
                    
                    # Get severity
                    severity = "Unknown"
                    metrics = cve_data.get("metrics", {})
                    for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
                        metric_list = metrics.get(metric_key, [])
                        if metric_list:
                            severity = metric_list[0].get("cvssData", {}).get("baseSeverity", "Unknown")
                            break
                    else:
                        cvss_v2 = metrics.get("cvssMetricV2", [])
                        if cvss_v2:
                            severity = cvss_v2[0].get("baseSeverity", "Unknown")
                    
                    cves.append({
                        "library": lib,
                        "cve_id": cve_id,
                        "description": desc[:200] + "..." if len(desc) > 200 else desc,
                        "severity": severity
                    })
                    
            elif response.status_code == 403:
                logger.warning(f"NVD API rate limited for {lib_base}.")
                
        except requests.exceptions.Timeout:
            logger.warning(f"NVD API timeout for {lib_base}")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Cannot reach NVD API for {lib_base}.")
        except Exception as e:
            logger.warning(f"CVE check error for {lib_base}: {e}")
        
        return cves

    def _check_cves(self, results: Dict[str, Any]):
        """
        Checks linked libraries against the NVD API for known CVEs.
        Uses ThreadPoolExecutor to check all libraries in PARALLEL.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        linked_libs = results.get("linked_libraries", [])
        if not linked_libs:
            return
        
        known_cves = []
        libs_to_check = linked_libs[:5]  # Limit to first 5
        
        # ── Performance: Parallel CVE lookups instead of sequential ──
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self._check_single_lib_cves, lib): lib 
                for lib in libs_to_check
            }
            for future in as_completed(futures):
                try:
                    cves = future.result(timeout=8)
                    known_cves.extend(cves)
                except Exception as e:
                    lib = futures[future]
                    logger.warning(f"CVE check failed for {lib}: {e}")
        
        results["known_cves"] = known_cves

    def _setup_decompiler(self, flat_api):
        from ghidra.app.decompiler import DecompInterface
        
        decomp = DecompInterface()
        decomp.openProgram(flat_api.getCurrentProgram())
        return decomp
