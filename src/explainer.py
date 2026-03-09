import os
from typing import Dict
from openai import OpenAI

class CodeExplainer:
    """
    Uses an LLM to explain decompiled code.
    """
    
    def __init__(self, provider: str = "local", model: str = "mistral", base_url: str = None, rag_manager=None):
        self.provider = provider
        self.model = model
        self.base_url = base_url
        self.rag_manager = rag_manager
        self._client = None
        
        api_key = os.environ.get("OPENAI_API_KEY", "dummy-key-for-local")
        
        if self.provider == "openai" and not self.base_url:
            # Standard OpenAI
            pass
        elif self.provider == "local" or self.base_url:
            # Local / Custom (e.g. Ollama)
            if not self.base_url:
                self.base_url = "http://localhost:11434/v1"
        
        self._client = OpenAI(api_key=api_key, base_url=self.base_url)

    def explain(self, code_map: Dict[str, str]) -> Dict[str, str]:
        """
        Generates explanations for the provided code.
        """
        explanations = {}
        system_prompt = (
            "You are a helpful reverse engineering assistant. "
            "Examine the provided decompiled C code and explain what it does "
            "in clear, natural language."
        )
        
        for func_name, code in code_map.items():
            if not code or code.startswith("// Decompilation failed"):
                explanations[func_name] = "Could not decompile function."
                continue
                
            user_prompt = f"Function Name: {func_name}\n\nCode:\n```c\n{code}\n```\n\nPlease explain this function."
            
            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ]
                )
                explanation = response.choices[0].message.content
                explanations[func_name] = explanation
            except Exception as e:
                explanations[func_name] = f"Error generating explanation: {str(e)}"
                
        return explanations

    def chat(self, messages: list) -> str:
        """
        Chat with the LLM. Includes RAG retrieval if rag_manager is present.
        Args:
            messages: List of {"role": "...", "content": "..."}
        """
        try:
            # 1. RAG Retrieval (if enabled)
            if self.rag_manager and messages:
                last_user_message = [m["content"] for m in messages if m["role"] == "user"]
                if last_user_message:
                    query = last_user_message[-1]
                    relevant_code = self.rag_manager.query_relevant_functions(query)
                    
                    if relevant_code:
                        context_str = "\n\n".join([f"Relevant Code Snippet:\n```c\n{c}\n```" for c in relevant_code])
                        
                        # Inject as a high-priority system message or prefix to the user prompt
                        rag_context = {
                            "role": "system", 
                            "content": (
                                "You are assisting a reverse engineer. "
                                "Here is relevant decompiled code found through semantic search that might help answer the user's question:\n\n"
                                f"{context_str}\n\n"
                                "Use this context to provide more accurate answers."
                            )
                        }
                        # Prepend the context to ensure the LLM sees it early
                        messages = [rag_context] + messages

            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error connecting to LLM or RAG: {str(e)}"

    def explain_security_report(self, report: dict) -> str:
        """
        Generates a natural language security assessment based on the report.
        """
        system_prompt = (
            "You are a Senior Security Auditor. Analyze the provided binary security report. "
            "Explain the implications of the findings in simple, professional terms. "
            "Highlight the risks associated with found flaws and missing mitigations. "
            "If vulnerable call sites are identified, explain the specific risk at each location. "
            "If known CVEs are found, explain their potential impact. "
            "Provide a final risk level (Low, Medium, High, Critical)."
        )
        
        # Format the report for the prompt
        mitigations_str = "\n".join([
            f"- {k}: {'ENABLED' if v is True else 'DISABLED' if v is False else v}" 
            for k, v in report.get("mitigations", {}).items()
        ])
        flaws_str = "\n".join([f"- {f}" for f in report.get("flaws", [])])
        
        if not flaws_str:
            flaws_str = "No specific flaws detected (static analysis)."

        # Fortified functions
        fortified = report.get("fortified_functions", [])
        fortify_str = ""
        if fortified:
            fortify_str = f"\n\nFortified Functions Found (FORTIFY_SOURCE):\n" + "\n".join([f"- {f}" for f in fortified])
        
        # Vulnerable call sites
        call_sites = report.get("vulnerable_call_sites", [])
        call_sites_str = ""
        if call_sites:
            call_sites_str = "\n\nVulnerable Call Sites (exact locations in decompiled code):\n"
            for site in call_sites[:15]:  # Limit to avoid overwhelming the prompt
                call_sites_str += f"- {site['dangerous_call']}() in function '{site['function']}' at line {site['line']}: `{site['context']}`\n"
        
        # Linked libraries
        libs = report.get("linked_libraries", [])
        libs_str = ""
        if libs:
            libs_str = "\n\nLinked Libraries:\n" + "\n".join([f"- {lib}" for lib in libs])
        
        # Known CVEs
        cves = report.get("known_cves", [])
        cve_str = ""
        if cves:
            cve_str = "\n\nKnown CVEs for Linked Libraries:\n"
            for cve in cves:
                cve_str += f"- [{cve['severity']}] {cve['cve_id']} ({cve['library']}): {cve['description']}\n"

        user_prompt = (
            f"Security Report:\n\n"
            f"Mitigations detected:\n{mitigations_str}\n\n"
            f"Potentially Dangerous Flaws detected:\n{flaws_str}"
            f"{fortify_str}"
            f"{call_sites_str}"
            f"{libs_str}"
            f"{cve_str}\n\n"
            f"Please provide a comprehensive textual security assessment."
        )

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating security explanation: {str(e)}"

    def explain_program(self, code_map: Dict[str, str]) -> str:
        """
        Generates a high-level summary of the entire program.
        """
        system_prompt = (
            "You are a Senior Reverse Engineer. Your goal is to explain the purpose "
            "and functionality of a binary program based on its decompiled source code. "
            "Focus on the high-level logic, user interactions, and specific algorithms used. "
            "Do not just explain line-by-line; synthesize the information into a coherent "
            "product description or capability summary."
        )

        # Heuristic: Focus on 'main' or 'entry', plus a few others if small
        # For now, let's limit context to avoid token limits by prioritizing 'main'
        context_code = ""
        
        # Priority 1: main
        if "main" in code_map:
            context_code += f"// Function: main\n{code_map['main']}\n\n"
            
        # Add others until some reasonable limit (simplistic approach)
        for name, code in code_map.items():
            if name == "main": 
                continue
            if len(context_code) > 12000: # Approx char limit for context
                context_code += f"\n// ... (trunctated other functions) ...\n"
                break
            context_code += f"// Function: {name}\n{code}\n\n"

        user_prompt = f"Decompiled Source Code:\n```c\n{context_code}\n```\n\nPlease provide a comprehensive natural language summary of what this program does."

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating program summary: {str(e)}"

    def explain_malware_report(self, report: dict) -> str:
        """
        Generates a natural language threat assessment based on malware behavior detection.
        """
        system_prompt = (
            "You are a Senior Malware Analyst and Threat Intelligence Expert. "
            "Analyze the provided malware behavioral indicator report from static analysis of a binary. "
            "Based on the detected indicators, determine:\n"
            "1. What TYPE of malware this likely is (trojan, backdoor, RAT, ransomware, worm, spyware, dropper, etc.)\n"
            "2. What the malware's PRIMARY OBJECTIVE appears to be\n"
            "3. What ATTACK TECHNIQUES (MITRE ATT&CK) are indicated\n"
            "4. How DANGEROUS this binary is and what damage it could cause\n"
            "5. Recommended RESPONSE actions\n"
            "Be specific and reference the actual findings. Provide a final THREAT LEVEL (Low/Medium/High/Critical)."
        )
        
        # Format findings by category
        findings_str = ""
        for category in report.get("categories", []):
            findings_str += f"\n{category['label']} ({category['count']} indicators):\n"
            for finding in category["findings"][:10]:  # Limit per category
                findings_str += (
                    f"  - [{finding['severity']}] {finding['description']} "
                    f"in function '{finding['function']}' line {finding['line']}: "
                    f"`{finding['code']}`\n"
                )
        
        severity = report.get("severity_counts", {})
        user_prompt = (
            f"Malware Behavioral Analysis Report:\n\n"
            f"Risk Score: {report.get('risk_score', 0)}/100\n"
            f"Risk Level: {report.get('risk_level', 'UNKNOWN')}\n"
            f"Total Indicators Found: {report.get('total_indicators', 0)}\n"
            f"  - CRITICAL: {severity.get('CRITICAL', 0)}\n"
            f"  - HIGH: {severity.get('HIGH', 0)}\n"
            f"  - MEDIUM: {severity.get('MEDIUM', 0)}\n"
            f"  - LOW: {severity.get('LOW', 0)}\n"
            f"\nDetailed Findings:{findings_str}\n\n"
            f"Please provide a comprehensive threat assessment and malware classification."
        )

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating malware assessment: {str(e)}"

