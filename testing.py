from openai import OpenAI

client = OpenAI(
    base_url="https://bedrock-runtime.ap-south-1.amazonaws.com/openai/v1", 
    api_key="ABSKQmVkcm9ja0FQSUtleS1kdjBnLWF0LTkzNTk1MTg3MDAwMTpBM2diZ1hmRm1mcUVLd2R6L1FRSjlvdGtkWjRBaHVaS0R2cjQ5ZXdYazh1OVZGV2c2OENVc2NWSGE5WT0=" # Replace with actual API key
)

completion = client.chat.completions.create(
    model="openai.gpt-oss-20b-1:0",
    messages=[
        {
            "role": "developer",
            "content": "You are a helpful assistant."
        },
        {
            "role": "user",
            "content": "Hello!"
        }
    ]
)

print(completion.choices[0].message)