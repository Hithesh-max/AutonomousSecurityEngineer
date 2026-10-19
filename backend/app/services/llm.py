import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class AIRemediator:
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")

    def generate_fix(self, finding_title: str, cwe: str, evidence: str) -> str:
        """
        Calls an LLM to generate a specific code patch and explanation.
        Raises ValueError if API key is missing.
        """
        prompt = f"""
You are an expert DevSecOps AI. Analyze the following security finding and provide a fix.

Vulnerability: {finding_title}
CWE: {cwe}
Evidence: {evidence}

Provide a detailed explanation of why this is dangerous, followed by a markdown code block containing the exact patch or remediation steps.
"""
        
        if not self.api_key:
            logger.error("No OPENAI_API_KEY found.")
            raise ValueError("OPENAI_API_KEY is not set. Cannot generate remediation.")
            
        try:
            from openai import OpenAI
            
            client = OpenAI(api_key=self.api_key)
            logger.info("Calling OpenAI API for remediation...")
            
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a DevSecOps AI."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
            )
            
            return response.choices[0].message.content
            
        except ImportError:
            logger.error("OpenAI package not installed.")
            raise ImportError("OpenAI package not installed.")
        except Exception as e:
            logger.error(f"AI API failed: {str(e)}")
            raise RuntimeError(f"AI API failed: {str(e)}")
