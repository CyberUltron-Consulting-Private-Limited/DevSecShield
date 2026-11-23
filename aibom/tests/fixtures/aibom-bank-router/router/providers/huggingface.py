from transformers import AutoModelForCausalLM

# supported model families (a catalog, not models this service runs)
SUPPORTED_MODELS = {
    "qwen2": ["Qwen2-0.5B", "Qwen2-1.5B", "Qwen2-7B", "Qwen2-72B"],
    "llama3": ["Llama-3-8B", "Llama-3-70B"],
}


def load_default():
    return AutoModelForCausalLM.from_pretrained("Qwen/Qwen2.5-1.5B-Instruct")
