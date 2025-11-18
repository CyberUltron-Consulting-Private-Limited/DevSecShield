import base64
from openai import NotGiven, OpenAI
from pydantic import BaseModel, Field
from dotenv import load_dotenv



def generate_structured_response(prompt:str,
                      model:str="gpt-4o",
                      output_model=None,
                      system_prompt:str=None,
                      image:bytes | None = None):
    """
    ### Generates a structued response for text or text + image input. 
    The returned value will be the output_model type model for structured outputs.
    Args :
    - promt : str => is the prompt for generating the response
    - system_prompt : str => system instructions for response generation
    - output_model => the structured output model that will be returned
    - image : bytes => the image bytes
    """
    
    load_dotenv()
    client = OpenAI()
    print("📝 Generating Structured response")

    if image:
        print("📷 Image input ")
        image_data = base64.b64encode(image).decode("ascii") #output is 'str'
        response = client.responses.parse(
            model=model,
            text_format=output_model,
            instructions= system_prompt,
            input=[
                {
                    "role": "user",
                    "content": [
                        { "type": "input_text", "text": prompt },
                        {
                            "type": "input_image",
                            "image_url": f"data:image/jpeg;base64,{image_data}",
                        },
                    ],
                }
            ],
            )
    
    else:
        print("⭐ Pure Text input ")
        response = client.responses.parse(
            model=model,
            text_format=output_model,
            instructions=system_prompt,
            input=prompt
        )
    
    model_response = response.output_parsed
    return model_response


def generate_response(prompt:str,
                      model:str="gpt-4o",
                      output_model=None,
                      system_prompt:str=None,
                      image:bytes | None = None)->str:
    """
    ### Generates a unstructured response for text or text + image input. 
    The returned value will be a string

    Args :
    - promt : str => is the prompt for generating the response
    - system_prompt : str => system instructions for response generation
    - output_model => the structured output model that will be returned
    - image : bytes => the image bytes
    """
    
    client = OpenAI()
    print("📝 Generating unstructured response")

    if image:
        print("📷 Image input ")
        image_data = base64.b64encode(image).decode("ascii") #output is 'str'
        response = client.responses.create(
                model="gpt-4.1",
                instructions=system_prompt,
                input=[
                    {
                        "role": "user",
                        "content": [
                            { "type": "input_text", "text": prompt },
                            {
                                "type": "input_image",
                                "image_url": f"data:image/jpeg;base64,{image_data}"
                            }
                        ]
                    }
                ]
            )
    
    else:
        print("⭐ Pure Text input ")
        response = client.responses.create(
            model=model,
            instructions=system_prompt,
            input=prompt
        )
    
    return response.output_text

    
        

