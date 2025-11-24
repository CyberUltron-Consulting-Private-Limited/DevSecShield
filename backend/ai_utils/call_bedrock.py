"""
AWS Bedrock LLM Provider
OpenAI GPT-OSS-20B-1:0 implementation via AWS Bedrock
"""

import json
import logging
from typing import Dict, Any, Optional
from django.conf import settings

logger = logging.getLogger(__name__)


class BedrockProvider:
    """AWS Bedrock LLM provider for OpenAI GPT-OSS-20B-1:0 - Production ready"""
    
    def __init__(self):
        try:
            import boto3
            self.boto3 = boto3
        except ImportError:
            raise ImportError(
                "boto3 is required for Bedrock provider. "
                "Install with: pip install boto3"
            )
        
        self.model_id = getattr(settings, 'BEDROCK_MODEL_ID', 'openai.gpt-oss-20b-1:0')
        self.region = getattr(settings, 'BEDROCK_REGION', 'ap-south-1')
        self.timeout = getattr(settings, 'BEDROCK_TIMEOUT', 60)
        
        # Initialize Bedrock client
        try:
            self.client = boto3.client(
                'bedrock-runtime',
                region_name=self.region
            )
            logger.info(f"Bedrock client initialized: model={self.model_id}, region={self.region}")
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {str(e)}")
            raise ValueError(
                f"Failed to initialize Bedrock: {str(e)}. "
                f"Check AWS credentials and region configuration."
            )
    
    def generate(
        self, 
        prompt: str, 
        max_tokens: int = 1000, 
        temperature: float = 0.3,
        system_message: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Generate text using AWS Bedrock OpenAI GPT-OSS-20B-1:0 model.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0.0-1.0)
            system_message: Optional system message
            **kwargs: Additional parameters
            
        Returns:
            Generated text response
        """
        try:
            return self._invoke_openai(prompt, max_tokens, temperature, system_message, **kwargs)
        except Exception as e:
            logger.error(f"Bedrock generation error: {str(e)}", exc_info=True)
            raise
    
    def _invoke_openai(
        self, 
        prompt: str, 
        max_tokens: int, 
        temperature: float,
        system_message: Optional[str] = None,
        **kwargs
    ) -> str:
        """Invoke OpenAI GPT-OSS-20B-1:0 model via Bedrock"""
        messages = []
        
        # Add system message if provided
        if system_message:
            messages.append({
                "role": "system",
                "content": system_message
            })
        
        # Add user message
        messages.append({
            "role": "user",
            "content": prompt
        })
        
        body = {
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        
        # Add optional parameters
        if 'top_p' in kwargs:
            body["top_p"] = kwargs['top_p']
        
        logger.debug(f"Calling Bedrock API: {self.model_id} (OpenAI format)")
        
        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(body),
                contentType='application/json',
                accept='application/json'
            )
            
            response_body = json.loads(response['body'].read())
            
            # Extract content from OpenAI response format
            # OpenAI models in Bedrock return: {"choices": [{"message": {"content": "..."}}]}
            if 'choices' in response_body and len(response_body['choices']) > 0:
                content = response_body['choices'][0].get('message', {}).get('content', '')
                logger.debug(f"Bedrock response received: {len(content)} chars")
                return content
            
            # Fallback extraction
            if 'content' in response_body:
                
                return response_body['content']
            if 'text' in response_body:
                return response_body['text']
            
            logger.warning(f"Unexpected response format: {response_body}")
            return str(response_body)
            
        except self.client.exceptions.ValidationException as e:
            logger.error(f"Bedrock validation error: {str(e)}")
            raise ValueError(f"Invalid Bedrock request: {str(e)}")
        except self.client.exceptions.AccessDeniedException as e:
            logger.error(f"Bedrock access denied: {str(e)}")
            raise ValueError(
                f"Access denied to Bedrock model. "
                f"Check IAM permissions and model access in Bedrock console."
            )
        except self.client.exceptions.ThrottlingException as e:
            logger.error(f"Bedrock throttling: {str(e)}")
            raise ValueError(f"Bedrock rate limit exceeded. Please retry after a moment.")
        except Exception as e:
            logger.error(f"Bedrock API error: {str(e)}")
            raise
    
    def is_available(self) -> bool:
        """Check if Bedrock is available"""
        try:
            # Try to list models (lightweight check)
            bedrock_client = self.boto3.client('bedrock', region_name=self.region)
            bedrock_client.list_foundation_models()
            return True
        except Exception as e:
            logger.warning(f"Bedrock availability check failed: {str(e)}")
            return False


def get_llm_provider() -> BedrockProvider:
    """
    Get Bedrock LLM provider instance.
    
    Returns:
        BedrockProvider instance
    """
    try:
        provider = BedrockProvider()
        logger.info("Using AWS Bedrock as LLM provider")
        return provider
    except Exception as e:
        logger.error(f"Failed to initialize Bedrock provider: {str(e)}")
        raise ValueError(
            f"Cannot initialize Bedrock provider: {str(e)}. "
            f"Please check AWS credentials and Bedrock configuration."
        )