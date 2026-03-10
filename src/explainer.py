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

    # Base system prompt always injected into chat
    _CHAT_SYSTEM_PROMPT = (
        "You are Hexplain, an expert AI assistant specializing in binary reverse engineering and malware analysis. "
        "You help analysts understand decompiled C code produced by Ghidra from binary executables.\n\n"
        "Your capabilities:\n"
        "- Explain what decompiled functions do in plain language\n"
        "- Identify suspicious patterns, dangerous calls, or malware-like behavior\n"
        "- Explain data structures, control flow, and algorithms found in decompiled code\n"
        "- Answer questions about security vulnerabilities present in the code\n"
        "- Suggest what a function's purpose might be based on its logic\n\n"
        "When the user asks about code currently being viewed, reference it specifically. "
        "If relevant code snippets are provided in the context, use them to give precise, grounded answers. "
        "Always be concise, technical, and helpful. Format your responses using Markdown."
    )

    def chat(self, messages: list) -> str:
        """
        Chat with the LLM. Includes RAG retrieval if rag_manager is present.
        Always injects a base system prompt and, when available, RAG code context.
        Args:
            messages: List of {"role": "...", "content": "..."}
        """
        try:
            final_messages = self._prepare_chat_messages(messages)
            response = self._client.chat.completions.create(
                model=self.model,
                messages=final_messages
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error connecting to LLM or RAG: {str(e)}"

    def chat_stream(self, messages: list):
        """
        Generator for streaming chat responses.
        """
        try:
            final_messages = self._prepare_chat_messages(messages)
            stream = self._client.chat.completions.create(
                model=self.model,
                messages=final_messages,
                stream=True
            )
            for chunk in stream:
                content = chunk.choices[0].delta.content
                if content:
                    yield content
        except Exception as e:
            yield f"Error in streaming: {str(e)}"

    def _prepare_chat_messages(self, messages: list) -> list:
        """Helper to inject system prompt and RAG context into message list."""
        final_messages = []

        # 1. Always inject the base system prompt first
        final_messages.append({
            "role": "system",
            "content": self._CHAT_SYSTEM_PROMPT
        })

        # 2. RAG Retrieval — find semantically relevant code snippets
        if self.rag_manager and messages:
            last_user_messages = [m["content"] for m in messages if m["role"] == "user"]
            if last_user_messages:
                query = last_user_messages[-1]
                relevant_code = self.rag_manager.query_relevant_functions(query, n_results=3)

                if relevant_code:
                    context_str = "\n\n---\n\n".join([
                        f"**Relevant Function (from binary):**\n```c\n{c}\n```"
                        for c in relevant_code
                    ])
                    final_messages.append({
                        "role": "system",
                        "content": (
                            "The following decompiled code snippets were retrieved from the indexed binary "
                            "based on semantic similarity to the user's question. "
                            "Use these as your primary reference when answering:\n\n"
                            f"{context_str}"
                        )
                    })

        # 3. Append any system context messages sent from the frontend
        for msg in messages:
            if msg.get("role") == "system":
                final_messages.append(msg)

        # 4. Append the actual user/assistant conversation history
        for msg in messages:
            if msg.get("role") in ("user", "assistant"):
                final_messages.append(msg)
        
        return final_messages

    def explain_security_report(self, report: dict, vt_report: dict = None) -> str:
        """
        Generates a natural language security assessment based on the report.
        Incorporates VirusTotal scan results when available for a complete threat picture.
        """
        system_prompt = (
            "You are a Senior Security Auditor and Malware Analyst. "
            "You have been given a complete security analysis of a binary, including:\n"
            "  1. Binary hardening mitigations (NX, Canary, PIE, RELRO, FORTIFY)\n"
            "  2. Dangerous function usage and vulnerable call sites\n"
            "  3. Linked library CVEs\n"
            "  4. VirusTotal multi-AV scan results (threat intelligence)\n"
            "Synthesize ALL of this information into a unified, professional security assessment. "
            "If the file is flagged by AV engines, treat this as the highest-priority finding. "
            "Explain the implications of all findings clearly. "
            "Provide a final overall risk level (Low, Medium, High, Critical)."
        )
        
        # ── VirusTotal Context ──
        vt_section = ""
        if vt_report:
            if vt_report.get("available"):
                stats = vt_report.get("stats", {})
                detections = vt_report.get("detections", [])
                vt_section = (
                    f"\n=== VirusTotal Threat Intelligence ===\n"
                    f"Verdict: {vt_report.get('verdict', 'UNKNOWN')}\n"
                    f"Detection Ratio: {vt_report.get('detection_ratio', 'N/A')} "
                    f"({stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious "
                    f"out of {stats.get('total_engines', 0)} AV engines)\n"
                )
                if detections:
                    vt_section += "Flagged by:\n"
                    for d in detections[:8]:
                        vt_section += f"  - [{d['category'].upper()}] {d['engine']}: {d['result']}\n"
                meta = vt_report.get("metadata", {})
                if meta.get("popular_threat_label"):
                    vt_section += f"Threat Family: {meta['popular_threat_label']}\n"
                vt_section += f"VT Link: {vt_report.get('vt_link', '')}\n"
            elif vt_report.get("not_found"):
                vt_section = "\n=== VirusTotal ===\nHash not found in VirusTotal (novel or locally-built binary).\n"
            else:
                vt_section = f"\n=== VirusTotal ===\nScan unavailable: {vt_report.get('error', '')}\n"

        # ── Mitigations & Flaws ──
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
            for site in call_sites[:15]:
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
            f"{vt_section}"
            f"\n=== Binary Security Report ===\n"
            f"Mitigations detected:\n{mitigations_str}\n\n"
            f"Potentially Dangerous Flaws detected:\n{flaws_str}"
            f"{fortify_str}"
            f"{call_sites_str}"
            f"{libs_str}"
            f"{cve_str}\n\n"
            f"Please provide a comprehensive security assessment combining ALL sources above."
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

    def explain_program(self, code_map: Dict[str, str], vt_report: dict = None, security_report: dict = None, malware_report: dict = None) -> str:
        """
        Generates a high-level summary of the entire program as a narrative report.
        Following user's specific formatting and role requirements.
        """
        system_prompt = (
            "You are generating a non-technical explanation of a software program based on analysis results.\n\n"
            "Write a one-page summary in simple, clear language that can be understood by someone without a technical background.\n\n"
            "Important instructions:\n"
            "- Do NOT use technical terms such as API names, memory addresses, assembly instructions, or cybersecurity jargon.\n"
            "- Do NOT use bullet points, headings, or lists.\n"
            "- Write in paragraph format only.\n"
            "- Avoid overly complex vocabulary.\n"
            "- Do not speculate beyond the provided data.\n\n"
            "The summary must:\n"
            "1. Clearly explain the main purpose of the program.\n"
            "2. Describe what the program does when it runs.\n"
            "3. Explain how it interacts with the system or the internet (if applicable) in simple terms.\n"
            "4. Mention whether the behavior appears normal, suspicious, or potentially harmful.\n"
            "5. End with a clear overall conclusion about what type of program it appears to be.\n\n"
            "Keep the explanation professional, neutral, and easy to read. The length should be approximately 250–400 words."
        )

        analysis_data = ""
        if security_report:
            analysis_data += f"\n[Security Analysis Summary]\n{security_report}\n"
        if malware_report:
            analysis_data += f"\n[Malware Behavioral Summary]\n{malware_report}\n"
        if vt_report:
            analysis_data += f"\n[VirusTotal Threat Context]\n{vt_report}\n"

        # ── Decompiled Code Context ──
        context_code = ""
        # Prioritize 'main' or important looking functions
        if "main" in code_map:
            context_code += f"// Function: main\n{code_map['main']}\n\n"
        
        # Add other functions up to a limit (keep space for LLM to reason)
        for name, code in code_map.items():
            if name == "main": continue
            if len(context_code) > 10000:
                context_code += f"\n// ... (truncated) ...\n"
                break
            context_code += f"// Function: {name}\n{code}\n\n"

        user_prompt = (
            f"Analysis Data:\n{analysis_data}\n\n"
            f"Decompiled Source Code Snippets:\n```c\n{context_code}\n```\n\n"
            f"Please generate the professional narrative summary based on this data."
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
            return f"Error generating program summary: {str(e)}"

    def explain_malware_report(self, report: dict) -> str:
        """
        Generates a natural language threat assessment based on VirusTotal scan results.
        """
        system_prompt = (
            "You are a Senior Malware Analyst and Threat Intelligence Expert. "
            "You have been provided with VirusTotal multi-AV scan results for a binary. "
            "Based on the analysis, determine:\n"
            "1. What TYPE of malware this likely is (trojan, backdoor, RAT, ransomware, worm, spyware, dropper, etc.)\n"
            "2. What the malware's PRIMARY OBJECTIVE appears to be\n"
            "3. What ATTACK TECHNIQUES (MITRE ATT&CK) are indicated\n"
            "4. How DANGEROUS this binary is and what damage it could cause\n"
            "5. Recommended RESPONSE actions\n"
            "Be specific and reference the actual findings. Provide a final THREAT LEVEL (Low/Medium/High/Critical)."
        )

        # ── VirusTotal Section ──
        vt = report.get("virustotal", {})
        if vt.get("available"):
            stats = vt.get("stats", {})
            detections = vt.get("detections", [])
            vt_section = (
                f"\n== VirusTotal Multi-AV Scan ==\n"
                f"Verdict: {vt.get('verdict', 'UNKNOWN')}\n"
                f"Detection Ratio: {vt.get('detection_ratio', 'N/A')} "
                f"({stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious "
                f"out of {stats.get('total_engines', 0)} engines)\n"
                f"VT Link: {vt.get('vt_link', '')}\n"
            )
            if detections:
                vt_section += "Top AV Detections:\n"
                for d in detections[:10]:
                    vt_section += f"  - [{d['category'].upper()}] {d['engine']}: {d['result']}\n"
            meta = vt.get("metadata", {})
            if meta.get("popular_threat_label"):
                vt_section += f"Threat Classification: {meta['popular_threat_label']}\n"
        elif vt.get("not_found"):
            vt_section = "\n== VirusTotal ==\nHash not found in VirusTotal database (novel or locally compiled binary).\n"
        else:
            vt_section = f"\n== VirusTotal ==\nNot available: {vt.get('error', 'Unknown reason')}\n"

        user_prompt = (
            f"Malware Analysis Report (VirusTotal Only):\n"
            f"Risk Score: {report.get('risk_score', 0)}/100\n"
            f"Risk Level: {report.get('risk_level', 'UNKNOWN')}\n"
            f"{vt_section}\n\n"
            f"Please provide a comprehensive threat assessment and malware classification based on the findings above."
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

