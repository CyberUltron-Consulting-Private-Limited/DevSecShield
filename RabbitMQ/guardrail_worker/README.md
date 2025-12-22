# List of Input Scanners : 

1. Anonymize 
2. Toxicity
3. TokenLimit
4. PromptInjection
5. Regex 
6. Code 
7. Secrets

## Meaning of the results : 

is_valid : Whether the input prompt was flagged by this scanner or not .
risk_score : The risk score of the input prompt.
sanitized_prompt : The sanitized prompt that was returned by the scanner.

# Inputs for each scanner : 

### Note : 
It is always assumed that if a scanner is enabled then its settings are fully present . if it is not enabled then the context for that scanner will be None .

## 1. Anonymize : 

```plaintext
The Anonymize Scanner acts as your digital guardian, ensuring your user prompts remain confidential and free from sensitive data exposure.

```

- preamble: Directs the LLM to bypass specific content.
- hidden_names: Transforms specified names to formats like [REDACTED_CUSTOM_1].
- threshold: Sets the acceptance threshold (Default: 0).
- allowed_names : List of names to be allowed to be present in the output.
- hidden_names : List of names to be redacted from the output.

## 2. Toxicity : 

```plaintext
The Toxicity Scanner provides a mechanism to analyze and mitigate the toxicity of text content, playing a crucial role in maintaining the health and safety of online interactions. This tool is instrumental in preventing the dissemination of harmful or offensive content.
```

- threshold: Sets the acceptance threshold (Default: 0).

## 3. TokenLimit : 

```plaintext
It ensures that prompts do not exceed a predetermined token count, helping prevent resource-intensive operations and potential denial of service attacks on large language models (LLMs).
```

- max_tokens: Maximum number of tokens to be allowed in the output.

## 4. PromptInjection : 

```plaintext
It is specifically tailored to guard against crafty input manipulations targeting large language models (LLM). By identifying and mitigating such attempts, it ensures the LLM operates securely without succumbing to injection attacks.
Attack scenario : 
Injection attacks, especially in the context of LLMs, can lead the model to perform unintended actions. There are two primary ways an attacker might exploit:
- Direct Injection: Directly overwrites system prompts.
- Indirect Injection: Alters inputs coming from external sources.
```

- threshold: Sets the acceptance threshold (Default: 0).

## 5. Regex : 

```plaintext
This scanner is designed to sanitize prompts based on predefined regular expression patterns. It offers flexibility in defining patterns to identify and process desirable or undesirable content within the prompts.
```

- regex_patterns: List of regex patterns to be used for detection.
- redact : Whether to redact the matched content or not.

## 6. Code : 

```plaintext
The Code Scanner ensures that prompts do not contain any code or executable content, helping prevent potential security vulnerabilities and resource-intensive operations.
```
```python
SUPPORTED_LANGUAGES = [
    "ARM Assembly",
    "AppleScript",
    "C",
    "C#",
    "C++",
    "COBOL",
    "Erlang",
    "Fortran",
    "Go",
    "Java",
    "JavaScript",
    "Kotlin",
    "Lua",
    "Mathematica/Wolfram Language",
    "PHP",
    "Pascal",
    "Perl",
    "PowerShell",
    "Python",
    "R",
    "Ruby",
    "Rust",
    "Scala",
    "Swift",
    "Visual Basic .NET",
    "jq",
]
```

- languages: List of languages to be allowed to be present in the output.
- is_blocked: Whether to block the code or not.

## 7. Secrets : 

```plaintext
This scanner diligently examines user inputs, ensuring that they don't carry any secrets before they are processed by the language model.
```

- redact_mode: Mode of redactiion to be used for the secrets. ( ``` REDACT_PARTIAL , REDACT_ALL , REDACT_HASH ``` )



### still thinking about these : 
1. Ban Topics
2. Ban Substrings

## Notes : 

When creating the REST API for users to use  allow users to select the input scanners they want to use and the score threshold they want to use.
The response should only have the input scanner results that they have selected . So dynamically create the response JSON . 