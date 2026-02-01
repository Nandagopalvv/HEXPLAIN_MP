import os
from typing import Dict
from openai import OpenAI

class CodeExplainer:
    """
    Uses an LLM to explain decompiled code.
    """
    
    def __init__(self, provider: str = "local", model: str = "mistral", base_url: str = None):
        self.provider = provider
        self.model = model
        self.base_url = base_url
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
        Chat with the LLM.
        Args:
            messages: List of {"role": "...", "content": "..."}
        """
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error connecting to LLM: {str(e)}"

    def explain_security_report(self, report: dict) -> str:
        """
        Generates a natural language security assessment based on the report.
        """
        system_prompt = (
            "You are a Senior Security Auditor. Analyze the provided binary security report. "
            "Explain the implications of the findings in simple, professional terms. "
            "Highlight the risks associated with found flaws and missing mitigations. "
            "Provide a final risk level (Low, Medium, High, Critical)."
        )
        
        # Format the report for the prompt
        mitigations_str = "\n".join([f"- {k}: {'ENABLED' if v else 'DISABLED' if v is False else v}" for k,v in report.get("mitigations", {}).items()])
        flaws_str = "\n".join([f"- {f}" for f in report.get("flaws", [])])
        
        if not flaws_str:
            flaws_str = "No specific flaws detected (static analysis)."

        user_prompt = (
            f"Security Report:\n\n"
            f"Mitigations detected:\n{mitigations_str}\n\n"
            f"Potentially Dangerous Flaws detected:\n{flaws_str}\n\n"
            f"Please provide a textual security assessment."
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
