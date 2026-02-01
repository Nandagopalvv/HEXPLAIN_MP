import argparse
import os
import sys
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from src.analyzer import GhidraAnalyzer
from src.explainer import CodeExplainer

def main():
    console = Console()
    
    parser = argparse.ArgumentParser(description="Hexplain: Reverse Engineering with AI")
    parser.add_argument("binary", help="Path to the binary file to analyze")
    parser.add_argument("--function", "-f", help="Specific function name to analyze (default: main/entry)")
    parser.add_argument("--model", "-m", default="mistral", help="LLM model to use (default: mistral)")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI explanation, just show decompilation")
    
    args = parser.parse_args()
    
    binary_path = args.binary
    if not os.path.exists(binary_path):
        console.print(f"[bold red]Error:[/bold red] Binary file not found: {binary_path}")
        sys.exit(1)
        
    console.print(Panel(f"Analyzing [bold green]{binary_path}[/bold green]", title="Hexplain"))
    
    # 1. Analyze
    try:
        with console.status("[bold blue]Running Ghidra analysis...[/bold blue]"):
            analyzer = GhidraAnalyzer(binary_path)
            decompiled_functions = analyzer.decompile(args.function)
            
        if not decompiled_functions:
            console.print("[yellow]No functions found or decompiled.[/yellow]")
            return

        console.print(f"[green]Successfully decompiled {len(decompiled_functions)} function(s).[/green]")
        
    except Exception as e:
        console.print(f"[bold red]Analysis Error:[/bold red] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
        
    # 2. Explain
    if args.no_ai:
        for name, code in decompiled_functions.items():
            console.print(Panel(code, title=f"Decompiled: {name}", highlight=True))
    else:
        # Check for API Key
        # Check for API Key (only warn, don't exit, as local models might be used)
        if not os.environ.get("OPENAI_API_KEY"):
            # If we are using a local model, this is fine. If not, CodeExplainer might complain later.
            pass

        explainer = CodeExplainer(model=args.model)
        
        with console.status("[bold purple]Generating explanations...[/bold purple]"):
            explanations = explainer.explain(decompiled_functions)
            
        for name, explanation in explanations.items():
            code = decompiled_functions[name]
            
            # Print Code
            console.print(Panel(code, title=f"Decompiled: {name}", highlight=True, expand=False))
            
            # Print Explanation
            console.print(Panel(Markdown(explanation), title=f"AI Explanation: {name}", border_style="purple"))

if __name__ == "__main__":
    main()
