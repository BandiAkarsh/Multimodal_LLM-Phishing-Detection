"""
LLM-Powered Explainability Engine for Phishing Detection

This module provides human-readable explanations for why a URL was classified
as phishing, legitimate, AI-generated phishing, or phishing kit.

Uses a smaller, faster LLM (Qwen2.5-1.5B) for chat/explanation generation.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig


class ExplainabilityEngine:
    """
    LLM-powered explainability engine for phishing detection explanations.
    
    Uses Qwen2.5-1.5B-Instruct (smaller, faster model) for generating
    human-readable explanations of detection results.
    """

    def __init__(
        self,
        model_name: str = "Qwen/Qwen2.5-1.5B-Instruct",
        device: Optional[str] = None
    ):
        """
        Initialize the explainability engine.
        
        Args:
            model_name: HuggingFace model identifier
            device: Device to load model on ('cuda', 'cpu', or 'auto')
        """
        self.model_name = model_name
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        
        print(f"Loading explainability model: {model_name}")
        self._load_model()
        print(f"Explainability engine ready on {self.device}")

    def _load_model(self):
        """Load the smaller LLM model with quantization for efficiency."""
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_name,
            trust_remote_code=True
        )
        
        # 4-bit quantization for faster inference and lower memory
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )
        
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            quantization_config=quantization_config,
            device_map=self.device,
            trust_remote_code=True,
        )
        
        self.model.eval()

    def explain_detection(
        self,
        url: str,
        classification: str,
        confidence: float,
        features: Dict[str, Any],
        ml_prediction: Optional[Dict] = None,
        llm_analysis: Optional[Dict] = None,
        toolkit_detection: Optional[Dict] = None,
        typosquatting: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive explanation for a detection result.
        
        Args:
            url: The analyzed URL
            classification: Classification result (legitimate, phishing, etc.)
            confidence: Confidence score (0-1)
            features: Dictionary of extracted URL features
            ml_prediction: ML model prediction details
            llm_analysis: LLM classification analysis
            toolkit_detection: Phishing kit detection results
            typosquatting: Typosquatting detection results
            
        Returns:
            Dictionary containing explanation and supporting details
        """
        # Build context from all available data
        context = self._build_context(
            url, classification, confidence, features,
            ml_prediction, llm_analysis, toolkit_detection, typosquatting
        )
        
        # Generate main explanation using LLM
        explanation = self._generate_explanation(context)
        
        # Extract key factors that influenced the decision
        key_factors = self._extract_key_factors(
            features, ml_prediction, llm_analysis, toolkit_detection, typosquatting
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(classification, key_factors)
        
        return {
            "url": url,
            "classification": classification,
            "confidence": confidence,
            "explanation": explanation,
            "key_factors": key_factors,
            "recommendations": recommendations,
            "technical_details": {
                "features_analyzed": len(features),
                "model_used": self.model_name,
                "device": self.device,
            }
        }

    def _build_context(
        self,
        url: str,
        classification: str,
        confidence: float,
        features: Dict[str, Any],
        ml_prediction: Optional[Dict],
        llm_analysis: Optional[Dict],
        toolkit_detection: Optional[Dict],
        typosquatting: Optional[Dict],
    ) -> str:
        """Build context string for LLM prompt."""
        
        context_parts = [
            f"URL: {url}",
            f"Classification: {classification.upper()}",
            f"Confidence: {confidence * 100:.1f}%",
            "",
            "=== URL Features ===",
        ]
        
        # Add relevant features (filter to most important ones)
        important_features = [
            "domain_length", "num_subdomains", "has_ip", "has_https",
            "suspicious_tld", "num_digits", "num_special_chars",
            "has_login_form", "num_external_links", "has_iframe",
            "domain_age_days", "alexa_rank", "has_redirect"
        ]
        
        for key in important_features:
            if key in features and features[key] is not None:
                context_parts.append(f"  {key}: {features[key]}")
        
        # Add ML prediction details
        if ml_prediction:
            context_parts.extend([
                "",
                "=== ML Model Analysis ===",
                f"  Prediction: {ml_prediction.get('prediction', 'N/A')}",
                f"  Probability: {ml_prediction.get('probability', 'N/A')}",
            ])
        
        # Add LLM analysis
        if llm_analysis:
            context_parts.extend([
                "",
                "=== LLM Analysis ===",
                f"  Reasoning: {llm_analysis.get('reasoning', 'N/A')[:200]}",
            ])
        
        # Add toolkit detection
        if toolkit_detection and toolkit_detection.get("detected"):
            context_parts.extend([
                "",
                "=== Phishing Kit Detection ===",
                f"  Toolkit: {toolkit_detection.get('toolkit_name', 'Unknown')}",
                f"  Confidence: {toolkit_detection.get('confidence', 0) * 100:.1f}%",
            ])
        
        # Add typosquatting
        if typosquatting and typosquatting.get("is_typosquatting"):
            context_parts.extend([
                "",
                "=== Typosquatting Detection ===",
                f"  Impersonated Brand: {typosquatting.get('impersonated_brand', 'Unknown')}",
                f"  Method: {typosquatting.get('detection_method', 'N/A')}",
            ])
        
        return "\n".join(context_parts)

    def _generate_explanation(self, context: str) -> str:
        """Generate human-readable explanation using LLM."""
        
        system_prompt = """You are a cybersecurity expert explaining phishing detection results to a non-technical user.
Your goal is to provide clear, understandable explanations of why a URL was classified as phishing or legitimate.

Guidelines:
- Use simple language, avoid technical jargon
- Explain in 2-3 paragraphs maximum
- Focus on the "why" not the "how"
- Be specific about what made the decision
- If phishing, explain what red flags were found
- If legitimate, explain what positive signals were found
- End with a brief summary"""

        user_prompt = f"""Based on the following detection analysis, explain to a regular internet user why this URL was classified as it was:

{context}

Provide a clear, friendly explanation that helps them understand the result."""

        return self._generate_response(system_prompt, user_prompt, max_tokens=300)

    def _extract_key_factors(
        self,
        features: Dict[str, Any],
        ml_prediction: Optional[Dict],
        llm_analysis: Optional[Dict],
        toolkit_detection: Optional[Dict],
        typosquatting: Optional[Dict],
    ) -> List[Dict[str, Any]]:
        """Extract the key factors that influenced the classification."""
        
        factors = []
        
        # Check for high-risk features
        high_risk_features = {
            "has_ip": "Uses IP address instead of domain name",
            "has_login_form": "Contains login or password input forms",
            "suspicious_tld": "Uses suspicious top-level domain",
            "num_subdomains": "Excessive number of subdomains",
            "has_iframe": "Contains hidden iframe elements",
            "num_external_links": "Excessive external links",
            "has_redirect": "URL contains redirect parameters",
        }
        
        for feature, description in high_risk_features.items():
            if feature in features and features[feature]:
                if isinstance(features[feature], bool) and features[feature]:
                    factors.append({
                        "type": "url_feature",
                        "name": feature,
                        "description": description,
                        "risk_level": "high"
                    })
                elif isinstance(features[feature], (int, float)) and features[feature] > 0:
                    factors.append({
                        "type": "url_feature",
                        "name": feature,
                        "description": f"{description}: {features[feature]}",
                        "risk_level": "high"
                    })
        
        # Check toolkit detection
        if toolkit_detection and toolkit_detection.get("detected"):
            factors.append({
                "type": "toolkit",
                "name": "phishing_kit",
                "description": f"Detected {toolkit_detection.get('toolkit_name', 'phishing toolkit')} signatures",
                "risk_level": "critical"
            })
        
        # Check typosquatting
        if typosquatting and typosquatting.get("is_typosquatting"):
            factors.append({
                "type": "typosquatting",
                "name": "typosquatting",
                "description": f"Impersonates {typosquatting.get('impersonated_brand', 'known brand')}",
                "risk_level": "high"
            })
        
        # Add LLM analysis factor
        if llm_analysis and llm_analysis.get("reasoning"):
            factors.append({
                "type": "llm_analysis",
                "name": "ai_analysis",
                "description": llm_analysis.get("reasoning", "")[:150],
                "risk_level": "medium"
            })
        
        return factors[:5]  # Limit to top 5 factors

    def _generate_recommendations(
        self,
        classification: str,
        key_factors: List[Dict]
    ) -> List[str]:
        """Generate actionable recommendations based on classification."""
        
        recommendations = []
        
        if classification.lower() in ["phishing", "ai_generated_phishing", "phishing_kit"]:
            recommendations.extend([
                "Do NOT enter any personal information on this website",
                "Do NOT click any links or download files from this page",
                "Report this URL to your email provider or security team",
                "If you already entered information, consider changing your passwords",
                "Check your account for any unauthorized activity",
            ])
        elif classification.lower() == "legitimate":
            recommendations.extend([
                "This appears to be a legitimate website",
                "Always verify the URL before entering sensitive information",
                "Look for HTTPS in the address bar",
                "Be cautious of emails asking you to verify account details",
            ])
        
        return recommendations

    def _generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 512,
        temperature: float = 0.3,
    ) -> str:
        """Generate response using the LLM."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        
        text = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        
        model_inputs = self.tokenizer([text], return_tensors="pt").to(self.device)
        
        generated_ids = self.model.generate(
            **model_inputs,
            max_new_tokens=max_tokens,
            temperature=temperature,
            do_sample=True,
            top_p=0.9,
        )
        
        generated_ids = [
            output_ids[len(input_ids):]
            for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
        ]
        
        response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        
        return response.strip()

    def answer_followup(
        self,
        question: str,
        previous_context: Dict[str, Any]
    ) -> str:
        """Answer follow-up questions about a previous detection."""
        
        context_summary = f"""
Previous analysis:
- URL: {previous_context.get('url', 'N/A')}
- Classification: {previous_context.get('classification', 'N/A')}
- Confidence: {previous_context.get('confidence', 0) * 100:.1f}%
- Key factors: {', '.join([f['name'] for f in previous_context.get('key_factors', [])[:3]])}
"""
        
        system_prompt = """You are a cybersecurity expert answering follow-up questions about a phishing detection result.
Be helpful, clear, and concise. If you don't know something, say so."""
        
        user_prompt = f"""{context_summary}

User's follow-up question: {question}

Please answer the user's question based on the previous analysis."""

        return self._generate_response(system_prompt, user_prompt, max_tokens=200)


class LightweightExplainer:
    """
    Lightweight explainer that doesn't require loading an LLM.
    Uses rule-based explanations for faster response times.
    """
    
    @staticmethod
    def explain_detection(
        url: str,
        classification: str,
        confidence: float,
        features: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Generate explanation without LLM (rule-based)."""
        
        # Build explanation based on classification
        if classification.lower() in ["phishing", "ai_generated_phishing", "phishing_kit"]:
            explanation = LightweightExplainer._explain_phishing(
                url, features, classification
            )
        else:
            explanation = LightweightExplainer._explain_legitimate(url, features)
        
        # Extract key factors
        key_factors = LightweightExplainer._extract_factors(features, classification)
        
        return {
            "url": url,
            "classification": classification,
            "confidence": confidence,
            "explanation": explanation,
            "key_factors": key_factors,
            "recommendations": LightweightExplainer._get_recommendations(classification),
            "technical_details": {
                "features_analyzed": len(features),
                "model_used": "rule-based",
            }
        }
    
    @staticmethod
    def _explain_phishing(url: str, features: Dict, classification: str) -> str:
        """Rule-based phishing explanation."""
        
        reasons = []
        
        if features.get("has_ip"):
            reasons.append("uses an IP address instead of a domain name")
        if features.get("suspicious_tld"):
            reasons.append(f"uses a suspicious top-level domain ({features.get('suspicious_tld')})")
        if features.get("has_login_form"):
            reasons.append("contains login or password input forms")
        if features.get("num_subdomains", 0) > 3:
            reasons.append("has an unusually high number of subdomains")
        if features.get("num_digits", 0) > 5:
            reasons.append("contains excessive numbers in the domain")
        if features.get("has_iframe"):
            reasons.append("contains hidden iframe elements")
        if features.get("num_external_links", 0) > 10:
            reasons.append("has many external links (common in phishing)")
        
        if classification.lower() == "ai_generated_phishing":
            reasons.append("shows patterns typical of AI-generated phishing content")
        elif classification.lower() == "phishing_kit":
            reasons.append("shows signatures of known phishing toolkit software")
        
        if not reasons:
            reasons.append("shows multiple characteristics common to phishing sites")
        
        reason_text = "; ".join(reasons[:3])
        
        return f"This URL was classified as {classification.replace('_', ' ')} because it {reason_text}. Exercise caution when visiting this website."
    
    @staticmethod
    def _explain_legitimate(url: str, features: Dict) -> str:
        """Rule-based legitimate explanation."""
        
        positive_signals = []
        
        if features.get("has_https"):
            positive_signals.append("uses secure HTTPS connection")
        if features.get("alexa_rank") and features.get("alexa_rank") < 100000:
            positive_signals.append("is a well-known, established website")
        if features.get("domain_age_days", 0) > 365:
            positive_signals.append("has been registered for over a year")
        if not features.get("has_ip"):
            positive_signals.append("uses a proper domain name instead of IP")
        if not features.get("suspicious_tld"):
            positive_signals.append("uses a standard top-level domain")
        
        if positive_signals:
            signal_text = "; ".join(positive_signals[:2])
            return f"This URL appears to be legitimate because it {signal_text}. However, always remain vigilant when entering personal information online."
        else:
            return "This URL does not show obvious signs of phishing. However, always verify websites before entering sensitive information."

    @staticmethod
    def _extract_factors(features: Dict, classification: str) -> List[Dict]:
        """Extract key factors from features."""
        
        factors = []
        
        if features.get("has_ip"):
            factors.append({"type": "url_feature", "name": "has_ip", "description": "Uses IP address", "risk_level": "high"})
        if features.get("has_login_form"):
            factors.append({"type": "url_feature", "name": "has_login_form", "description": "Has login form", "risk_level": "high"})
        if features.get("suspicious_tld"):
            factors.append({"type": "url_feature", "name": "suspicious_tld", "description": f"Suspicious TLD: {features.get('suspicious_tld')}", "risk_level": "high"})
        if features.get("has_https"):
            factors.append({"type": "url_feature", "name": "has_https", "description": "Secure HTTPS", "risk_level": "low"})
        
        return factors[:5]

    @staticmethod
    def _get_recommendations(classification: str) -> List[str]:
        """Get recommendations based on classification."""
        
        if classification.lower() in ["phishing", "ai_generated_phishing", "phishing_kit"]:
            return [
                "Do NOT enter any personal information on this website",
                "Do NOT click any links or download files from this page",
                "Report this URL to your email provider or security team",
            ]
        else:
            return [
                "This appears to be a legitimate website",
                "Always verify the URL before entering sensitive information",
            ]


# Factory function to get appropriate explainer
def get_explainer(use_llm: bool = True, model_name: str = "Qwen/Qwen2.5-1.5B-Instruct") -> Any:
    """
    Factory function to get the appropriate explainer.
    
    Args:
        use_llm: Whether to use LLM-based explainer (slower but more detailed)
        model_name: Model to use for LLM explainer
        
    Returns:
        ExplainabilityEngine or LightweightExplainer instance
    """
    if use_llm:
        return ExplainabilityEngine(model_name=model_name)
    else:
        return LightweightExplainer()