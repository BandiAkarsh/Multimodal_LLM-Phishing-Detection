"""
MLLM Feature Transformer for Phishing Detection

This module uses a Multimodal Large Language Model (MLLM) to analyze websites
and classify them into 4 categories:

1. LEGITIMATE - Safe, authentic website
2. PHISHING - Traditional phishing (manual attack)
3. AI_GENERATED_PHISHING - Phishing created using AI tools (ChatGPT, etc.)
4. PHISHING_KIT - Phishing created using toolkits (Gophish, HiddenEye, etc.)

The MLLM analyzes:
- URL structure and patterns
- HTML/DOM content
- Visual layout (if screenshot provided)
- Linguistic patterns (to detect AI-generated content)
- Toolkit signatures (form structure, parameter names, etc.)
"""

from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch
import re
import json
from enum import Enum
from typing import Dict, Any, Optional, Tuple

class ThreatCategory(str, Enum):
    """Classification categories for phishing detection."""
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    AI_GENERATED_PHISHING = "ai_generated_phishing"
    PHISHING_KIT = "phishing_kit"


class MLLMFeatureTransformer:
    """
    Multimodal LLM-based feature transformer for advanced phishing detection.
    
    This class uses a quantized LLM (Qwen2.5-3B) to analyze website metadata
    and classify threats into 4 categories. It's optimized for 4GB VRAM GPUs.
    """
    
    def __init__(self, model_name="Qwen/Qwen2.5-3B-Instruct"):
        """
        Initialize the MLLM transformer.
        
        Args:
            model_name: HuggingFace model identifier (default: Qwen2.5-3B-Instruct)
        """
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        # 4-bit quantization configuration for 4GB VRAM optimization
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )
        
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            quantization_config=quantization_config,
            device_map="auto",
            trust_remote_code=True
        )
        
        # AI-generated content indicators
        self.ai_indicators = {
            'phrases': [
                'as an ai', 'i cannot', 'i am unable', 'it is important to',
                'please note that', 'in conclusion', 'furthermore', 'moreover',
                'it is worth noting', 'in order to', 'at the end of the day',
                'in the event that', 'with that being said', 'needless to say'
            ],
            'patterns': [
                r'(?i)(dear\s+valued?\s+customer)',
                r'(?i)(your\s+account\s+has\s+been\s+(?:suspended|locked|compromised))',
                r'(?i)(verify\s+your\s+(?:identity|account|information)\s+immediately)',
                r'(?i)(failure\s+to\s+(?:verify|respond|confirm)\s+will\s+result)',
                r'(?i)(we\s+(?:have\s+)?noticed\s+(?:some\s+)?(?:suspicious|unusual)\s+activity)',
                r'(?i)(click\s+(?:the\s+)?(?:link|button)\s+(?:below|here)\s+to\s+(?:verify|confirm|secure))',
            ]
        }
    
    def transform_to_text(self, metadata: Dict[str, Any]) -> str:
        """
        Transform multimodal metadata into a descriptive text feature using MLLM.
        
        Args:
            metadata: Dictionary containing URL features, HTML content summary, etc.
            
        Returns:
            str: Generated textual description of the website's suspicion level.
        """
        prompt = self._create_prompt(metadata)
        messages = [
            {"role": "system", "content": self._get_system_prompt()},
            {"role": "user", "content": prompt}
        ]
        
        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        
        model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)
        
        generated_ids = self.model.generate(
            **model_inputs,
            max_new_tokens=512
        )
        
        generated_ids = [
            output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
        ]
        
        response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        return response
    
    def classify_threat(self, metadata: Dict[str, Any], toolkit_signatures: Optional[Dict] = None) -> Tuple[ThreatCategory, float, str]:
        """
        Classify the website into one of 4 threat categories.
        
        This is the main classification method that:
        1. Checks for toolkit signatures (Gophish, HiddenEye, etc.)
        2. Analyzes content for AI-generated patterns
        3. Uses MLLM for deep analysis
        
        Args:
            metadata: Dictionary containing URL features, HTML content, etc.
            toolkit_signatures: Pre-detected toolkit signatures from web_scraper
            
        Returns:
            Tuple of (ThreatCategory, confidence, explanation)
        """
        # Priority 1: Check for toolkit signatures (most reliable)
        if toolkit_signatures and toolkit_signatures.get('detected'):
            toolkit_name = toolkit_signatures.get('toolkit_name', 'Unknown Toolkit')
            confidence = toolkit_signatures.get('confidence', 0.9)
            explanation = self._explain_toolkit_detection(toolkit_signatures)
            return ThreatCategory.PHISHING_KIT, confidence, explanation
        
        # Priority 2: Check for AI-generated content patterns
        html_content = metadata.get('html', '')
        text_content = metadata.get('text_content', '')
        content_to_analyze = text_content or html_content
        
        ai_score, ai_indicators = self._detect_ai_generated_content(content_to_analyze, metadata)
        
        # Priority 3: Use MLLM for comprehensive analysis
        prompt = self._create_classification_prompt(metadata, ai_indicators)
        messages = [
            {"role": "system", "content": self._get_classification_system_prompt()},
            {"role": "user", "content": prompt}
        ]
        
        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        
        model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)
        
        generated_ids = self.model.generate(
            **model_inputs,
            max_new_tokens=300,
            temperature=0.1  # Low temperature for more deterministic output
        )
        
        generated_ids = [
            output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
        ]
        
        response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        
        # Parse MLLM response
        category, confidence, explanation = self._parse_classification_response(response, ai_score)
        
        return category, confidence, explanation
    
    def _detect_ai_generated_content(self, content: str, metadata: Dict[str, Any]) -> Tuple[float, list]:
        """
        Detect if content appears to be AI-generated.
        
        AI-generated phishing often has:
        - Overly formal language
        - Perfect grammar
        - Generic phrases
        - Lack of specific details
        
        Args:
            content: Text content from the page
            metadata: Additional metadata
            
        Returns:
            Tuple of (ai_score 0-1, list of detected indicators)
        """
        if not content:
            return 0.0, []
        
        content_lower = content.lower()
        detected_indicators = []
        score = 0.0
        
        # Check for AI-typical phrases
        for phrase in self.ai_indicators['phrases']:
            if phrase in content_lower:
                detected_indicators.append(f"AI phrase: '{phrase}'")
                score += 0.1
        
        # Check for phishing patterns (often in AI-generated phishing)
        for pattern in self.ai_indicators['patterns']:
            if re.search(pattern, content):
                match = re.search(pattern, content)
                detected_indicators.append(f"Suspicious pattern: '{match.group()[:50]}...'")
                score += 0.15
        
        # Check for urgency language (common in AI-generated phishing)
        urgency_words = ['immediately', 'urgent', 'expires', 'suspended', 'locked', 'verify now', 'act now']
        urgency_count = sum(1 for word in urgency_words if word in content_lower)
        if urgency_count >= 2:
            detected_indicators.append(f"Multiple urgency words ({urgency_count})")
            score += 0.2
        
        # Check for generic greetings (AI tends to use these)
        generic_greetings = ['dear customer', 'dear user', 'dear valued', 'dear member', 'dear account holder']
        for greeting in generic_greetings:
            if greeting in content_lower:
                detected_indicators.append(f"Generic greeting: '{greeting}'")
                score += 0.15
                break
        
        # Check DOM structure from metadata
        dom_structure = metadata.get('dom_structure', {})
        if dom_structure:
            # AI-generated phishing pages often have minimal but well-structured content
            num_links = dom_structure.get('num_links', 0)
            num_forms = dom_structure.get('num_forms', 0)
            has_login = dom_structure.get('has_login_form', False)
            
            if has_login and num_links < 5 and num_forms <= 2:
                detected_indicators.append("Minimal page with login form (potential phishing landing)")
                score += 0.2
        
        # Cap score at 1.0
        score = min(1.0, score)
        
        return score, detected_indicators
    
    def _explain_toolkit_detection(self, toolkit_signatures: Dict) -> str:
        """Generate explanation for toolkit detection."""
        toolkit_name = toolkit_signatures.get('toolkit_name', 'Unknown')
        signatures = toolkit_signatures.get('signatures_found', [])
        
        explanation = f"PHISHING KIT DETECTED: {toolkit_name}\n"
        explanation += "Detected signatures:\n"
        for sig in signatures[:5]:  # Limit to 5 signatures
            explanation += f"  - {sig}\n"
        
        return explanation
    
    def _get_system_prompt(self) -> str:
        """System prompt for descriptive analysis."""
        return """You are a cybersecurity analyst expert in detecting phishing websites. 
Analyze the provided website features and generate a detailed textual description of the site's characteristics and any suspicious patterns. 

Focus on:
1. URL structure anomalies
2. DOM/HTML structure (forms, inputs, iframes)
3. Content patterns (urgency, generic greetings)
4. Signs of AI-generated content
5. Signs of phishing toolkit usage

Be specific and technical in your analysis."""
    
    def _get_classification_system_prompt(self) -> str:
        """System prompt for 4-category classification."""
        return """You are a cybersecurity expert specializing in phishing detection. 

You must classify websites into exactly ONE of these 4 categories:

1. LEGITIMATE - Authentic, trustworthy website
2. PHISHING - Traditional manually-created phishing attack
3. AI_GENERATED_PHISHING - Phishing created using AI tools (ChatGPT, Claude, etc.)
   - Signs: Perfect grammar, generic phrasing, urgency language, formal tone
4. PHISHING_KIT - Phishing created using toolkits (Gophish, HiddenEye, King Phisher)
   - Signs: Standard form structures, tracking parameters (?rid=), minimal customization

Respond in this exact JSON format:
{
    "category": "CATEGORY_NAME",
    "confidence": 0.XX,
    "reasoning": "Brief explanation"
}

Be decisive. When in doubt between AI_GENERATED and regular PHISHING, look for the telltale AI patterns."""
    
    def _create_prompt(self, metadata: Dict[str, Any]) -> str:
        """Create structured prompt from metadata for descriptive analysis."""
        url = metadata.get('url', 'N/A')
        features = metadata.get('url_features', metadata.get('features', {}))
        html_summary = metadata.get('dom_structure', metadata.get('html_summary', 'N/A'))
        
        feature_desc = "\n".join([f"- {k}: {v}" for k, v in features.items()])
        if isinstance(html_summary, dict):
            html_desc = "\n".join([f"- {k}: {v}" for k, v in html_summary.items()])
        else:
            html_desc = str(html_summary)
        
        prompt = f"""
Analyze the following website data for potential phishing indicators:

URL: {url}

Extracted Features:
{feature_desc}

HTML Content Summary:
{html_desc}

Based on these features, describe the website's characteristics. Is it suspicious? If so, why? 
Provide a comprehensive description that highlights anomalies in the URL structure, domain features, or content.
"""
        return prompt
    
    def _create_classification_prompt(self, metadata: Dict[str, Any], ai_indicators: list) -> str:
        """Create prompt for 4-category classification."""
        url = metadata.get('url', 'N/A')
        features = metadata.get('url_features', metadata.get('features', {}))
        html_summary = metadata.get('dom_structure', metadata.get('html_summary', {}))
        typosquat = metadata.get('typosquatting', {})
        
        feature_desc = "\n".join([f"  - {k}: {v}" for k, v in features.items() if k != 'typosquatting'])
        
        if isinstance(html_summary, dict):
            html_desc = "\n".join([f"  - {k}: {v}" for k, v in html_summary.items()])
        else:
            html_desc = str(html_summary)
        
        ai_indicator_desc = ""
        if ai_indicators:
            ai_indicator_desc = "Detected AI-Content Indicators:\n" + "\n".join([f"  - {ind}" for ind in ai_indicators])
        
        typosquat_desc = ""
        if typosquat and typosquat.get('is_typosquatting'):
            typosquat_desc = f"""
Typosquatting Detection:
  - Is Typosquatting: {typosquat.get('is_typosquatting')}
  - Method: {typosquat.get('detection_method')}
  - Impersonated Brand: {typosquat.get('impersonated_brand', 'N/A')}
"""
        
        prompt = f"""Classify this website into one of the 4 categories.

URL: {url}

URL Features:
{feature_desc}

DOM Structure:
{html_desc}

{typosquat_desc}

{ai_indicator_desc}

Respond with the JSON classification only."""
        
        return prompt
    
    def _parse_classification_response(self, response: str, ai_score: float) -> Tuple[ThreatCategory, float, str]:
        """
        Parse MLLM response and extract classification.
        
        Args:
            response: Raw MLLM response
            ai_score: Pre-computed AI detection score
            
        Returns:
            Tuple of (ThreatCategory, confidence, explanation)
        """
        # Try to extract JSON from response
        try:
            # Find JSON in response
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                data = json.loads(json_str)
                
                category_str = data.get('category', 'PHISHING').upper()
                confidence = float(data.get('confidence', 0.7))
                reasoning = data.get('reasoning', 'MLLM analysis')
                
                # Map to enum
                category_map = {
                    'LEGITIMATE': ThreatCategory.LEGITIMATE,
                    'PHISHING': ThreatCategory.PHISHING,
                    'AI_GENERATED_PHISHING': ThreatCategory.AI_GENERATED_PHISHING,
                    'AI_GENERATED': ThreatCategory.AI_GENERATED_PHISHING,
                    'PHISHING_KIT': ThreatCategory.PHISHING_KIT,
                    'TOOLKIT': ThreatCategory.PHISHING_KIT,
                }
                
                category = category_map.get(category_str, ThreatCategory.PHISHING)
                
                # If we detected high AI score but MLLM said regular phishing, override
                if ai_score >= 0.5 and category == ThreatCategory.PHISHING:
                    category = ThreatCategory.AI_GENERATED_PHISHING
                    reasoning += f" [AI content score: {ai_score:.2f}]"
                
                return category, confidence, reasoning
                
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            pass
        
        # Fallback: Parse text response
        response_lower = response.lower()
        
        if 'legitimate' in response_lower and 'not' not in response_lower[:50]:
            return ThreatCategory.LEGITIMATE, 0.7, response[:200]
        elif 'ai_generated' in response_lower or 'ai-generated' in response_lower or ai_score >= 0.5:
            return ThreatCategory.AI_GENERATED_PHISHING, max(0.7, ai_score), response[:200]
        elif 'toolkit' in response_lower or 'phishing_kit' in response_lower:
            return ThreatCategory.PHISHING_KIT, 0.8, response[:200]
        else:
            return ThreatCategory.PHISHING, 0.75, response[:200]
