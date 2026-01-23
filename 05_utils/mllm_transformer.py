from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch

class MLLMFeatureTransformer:
    def __init__(self, model_name="Qwen/Qwen2.5-3B-Instruct"):
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
    
    def transform_to_text(self, metadata):
        """
        Transform multimodal metadata into a descriptive text feature using MLLM.
        
        Args:
            metadata (dict): Dictionary containing URL features, HTML content summary, etc.
            
        Returns:
            str: Generated textual description of the website's suspicion level.
        """
        prompt = self._create_prompt(metadata)
        messages = [
            {"role": "system", "content": "You are a cybersecurity analyst expert in detecting phishing websites. Analyze the provided website features and generate a detailed textual description of the site's characteristics and any suspicious patterns. Focus on the 'Why', not just the statistics."},
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
    
    def _create_prompt(self, metadata):
        # Create structured prompt from metadata
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
