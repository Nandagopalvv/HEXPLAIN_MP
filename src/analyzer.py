import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any

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

    def analyze_security(self) -> Dict[str, Any]:
        """
        Performs a security check on the binary.
        Checks for:
        - Dangerous functions
        - Security mitigations (NX, Canary, etc.)
        """
        results = {
            "flaws": [],
            "mitigations": {
                "Canary": False,
                "NX": True,  # Assume True until proven False
                "PIE": "Unknown" 
            }
        }
        
        from pyghidra import open_program
        
        with open_program(str(self.binary_path), analyze=True) as flat_api:
            program = flat_api.getCurrentProgram()
            
            # 1. Check for dangerous functions
            dangerous_funcs = ["gets", "strcpy", "strcat", "sprintf", "system", "execve", "popen"]
            symbol_table = program.getSymbolTable()
            
            for func_name in dangerous_funcs:
                # Check external symbols (imports)
                syms = symbol_table.getGlobalSymbols(func_name)
                if syms:
                    results["flaws"].append(f"Uses dangerous function: {func_name}")
            
            # 2. Check for Stack Canary
            # Look for __stack_chk_fail import
            chk_fail = symbol_table.getGlobalSymbols("__stack_chk_fail")
            if chk_fail:
                results["mitigations"]["Canary"] = True
            
            # 3. Check for NX (No-Execute)
            # Iterate memory blocks. If we find Writable AND Executable, NX is effectively off (or partial).
            memory = program.getMemory()
            blocks = memory.getBlocks()
            for block in blocks:
                # Only care about initialized blocks usually, or RAM
                if block.isExecute() and block.isWrite():
                    results["mitigations"]["NX"] = False
                    results["flaws"].append(f"Memory block {block.getName()} is W+X (Writable and Executable)")
            
            # 4. Check for PIE (simplistic)
            # If the image base is 0 or very low, it might be PIE/relocatable, 
            # but Ghidra often rebases. 
            # A better check is verifying file type properties or dynamic section.
            # For now, let's leave PIE as unknown or implement a heuristic if requested.
            
        return results

    def _setup_decompiler(self, flat_api):
        from ghidra.app.decompiler import DecompInterface
        
        decomp = DecompInterface()
        decomp.openProgram(flat_api.getCurrentProgram())
        return decomp
