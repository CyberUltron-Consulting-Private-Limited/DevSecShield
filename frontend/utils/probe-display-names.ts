/**
 * Display names for LLM/Garak security probes.
 * Use getProbeDisplayName(probe) for consistent display across charts, tables, and dialogs.
 * Keys use web_injection.* (matching probes_type.py); xss.* aliases kept for backward compatibility.
 * Display names are intentionally descriptive to help users understand what each benchmark tests.
 */

export const PROBE_DISPLAY_NAMES: Record<string, string> = {
  // ansiescape
  "ansiescape.AnsiEscaped": "ANSI escape handling: tests model's response to escaped control characters in text output",
  "ansiescape.AnsiRaw": "ANSI escape handling: tests model's response to raw ANSI control sequences",
  "ansiescape.AnsiRawTokenizerHF": "ANSI escape handling: tests HuggingFace tokenizer behavior with raw ANSI sequences",
  // apikey
  "apikey.CompleteKey": "API key leakage: tests if model can be tricked into revealing complete API keys or secrets",
  "apikey.GetKey": "API key leakage: tests if model can be prompted to extract or expose API keys",
  // atkgen
  "atkgen.Tox": "Attack generation: tests if model generates toxic or harmful content when prompted",
  // audio
  "audio.AudioAchillesHeel": "Audio safety: tests model's vulnerability to audio-based adversarial inputs (Achilles heel)",
  // av_spam_scanning
  "av_spam_scanning.EICAR": "AV/spam detection: EICAR test file — tests if model recognizes antivirus test patterns",
  "av_spam_scanning.GTUBE": "AV/spam detection: GTUBE — tests if model recognizes spam test patterns",
  "av_spam_scanning.GTphish": "AV/spam detection: GTphish — tests if model recognizes phishing test patterns",
  // badchars
  "badchars.BadCharacters": "Bad characters: tests model's handling of malformed or unexpected character sequences",
  // continuation
  "continuation.ContinueSlursReclaimedSlurs": "Continuation safety: tests if model continues or amplifies slurs and reclaimed slurs",
  "continuation.ContinueSlursReclaimedSlursFull": "Continuation safety: full test for slurs and reclaimed slurs continuation",
  // dan
  "dan.Ablation_Dan_11_0": "DAN jailbreak: Ablation variant 11.0 — tests resistance to Do Anything Now style jailbreaks",
  "dan.AntiDAN": "DAN jailbreak: Anti-DAN variant — tests resistance to anti-safety jailbreak prompts",
  "dan.AutoDAN": "DAN jailbreak: Auto variant — tests resistance to automated jailbreak generation",
  "dan.AutoDANCached": "DAN jailbreak: Auto variant (cached) — tests resistance to known auto jailbreak patterns",
  "dan.ChatGPT_Developer_Mode_RANTI": "DAN jailbreak: Developer mode RANTI — tests resistance to developer mode override prompts",
  "dan.ChatGPT_Developer_Mode_v2": "DAN jailbreak: Developer mode v2 — tests resistance to developer mode jailbreak",
  "dan.ChatGPT_Image_Markdown": "DAN jailbreak: Image markdown variant — tests jailbreak via markdown/image injection",
  "dan.DAN_Jailbreak": "DAN jailbreak: classic Do Anything Now — tests resistance to standard DAN-style prompts",
  "dan.DUDE": "DAN jailbreak: DUDE variant — tests resistance to DUDE jailbreak technique",
  "dan.DanInTheWild": "DAN jailbreak: in-the-wild prompts — tests resistance to real-world jailbreak attempts",
  "dan.DanInTheWildFull": "DAN jailbreak: in-the-wild prompts (full) — extended real-world jailbreak test",
  "dan.Dan_10_0": "DAN jailbreak: version 10.0 — tests resistance to DAN 10.0 jailbreak",
  "dan.Dan_11_0": "DAN jailbreak: version 11.0 — tests resistance to DAN 11.0 jailbreak",
  "dan.Dan_6_0": "DAN jailbreak: version 6.0 — tests resistance to DAN 6.0 jailbreak",
  "dan.Dan_6_2": "DAN jailbreak: version 6.2 — tests resistance to DAN 6.2 jailbreak",
  "dan.Dan_7_0": "DAN jailbreak: version 7.0 — tests resistance to DAN 7.0 jailbreak",
  "dan.Dan_8_0": "DAN jailbreak: version 8.0 — tests resistance to DAN 8.0 jailbreak",
  "dan.Dan_9_0": "DAN jailbreak: version 9.0 — tests resistance to DAN 9.0 jailbreak",
  "dan.STAN": "DAN jailbreak: STAN variant — tests resistance to STAN jailbreak technique",
  // divergence
  "divergence.Repeat": "Divergence: repeat — tests if model diverges or fails when given repetitive input",
  "divergence.RepeatExtended": "Divergence: repeat extended — extended test for repetition-induced model divergence",
  "divergence.RepeatedToken": "Divergence: repeated token — tests model behavior with repeated token sequences",
  // doctor
  "doctor.Bypass": "Medical safety: doctor bypass — tests if model can be prompted to give medical advice without disclaimers",
  "doctor.BypassLeet": "Medical safety: doctor bypass (leet) — tests medical advice bypass using leetspeak obfuscation",
  "doctor.Puppetry": "Medical safety: puppetry — tests if model can be made to role-play as unqualified medical advisor",
  // donotanswer
  "donotanswer.DiscriminationExclusionToxicityHatefulOffensive": "Do not answer: discrimination/toxicity — tests if model refuses discriminatory or hateful content",
  "donotanswer.HumanChatbox": "Do not answer: human chatbox — tests if model refuses to impersonate unrestricted human chat",
  "donotanswer.InformationHazard": "Do not answer: information hazard — tests if model refuses to output dangerous information",
  "donotanswer.MaliciousUses": "Do not answer: malicious uses — tests if model refuses requests for malicious purposes",
  "donotanswer.MisinformationHarms": "Do not answer: misinformation harms — tests if model refuses to generate harmful misinformation",
  // dra
  "dra.DRA": "Direct request attack (DRA): tests resistance to direct prompts for harmful or restricted content",
  "dra.DRAAdvanced": "Direct request attack (DRA) advanced: extended direct request attack resistance testing",
  // encoding
  "encoding.InjectAscii85": "Encoding injection: ASCII85 — tests if model output can carry hidden payloads in ASCII85 encoding",
  "encoding.InjectAtbash": "Encoding injection: Atbash cipher — tests payload injection via Atbash encoding",
  "encoding.InjectBase16": "Encoding injection: Base16 — tests payload injection via Base16/hex encoding",
  "encoding.InjectBase2048": "Encoding injection: Base2048 — tests payload injection via Base2048 encoding",
  "encoding.InjectBase32": "Encoding injection: Base32 — tests payload injection via Base32 encoding",
  "encoding.InjectBase64": "Encoding injection: Base64 — tests payload injection via Base64 encoding",
  "encoding.InjectBraille": "Encoding injection: Braille — tests payload injection via Braille characters",
  "encoding.InjectEcoji": "Encoding injection: Ecoji — tests payload injection via Ecoji encoding",
  "encoding.InjectHex": "Encoding injection: Hex — tests payload injection via hexadecimal encoding",
  "encoding.InjectLeet": "Encoding injection: Leet speak — tests payload injection via leetspeak obfuscation",
  "encoding.InjectMime": "Encoding injection: MIME — tests payload injection via MIME encoding",
  "encoding.InjectMorse": "Encoding injection: Morse — tests payload injection via Morse code",
  "encoding.InjectNato": "Encoding injection: NATO phonetic — tests payload injection via NATO alphabet",
  "encoding.InjectQP": "Encoding injection: quoted-printable — tests payload injection via QP encoding",
  "encoding.InjectROT13": "Encoding injection: ROT13 — tests payload injection via ROT13 cipher",
  "encoding.InjectSneakyBits": "Encoding injection: sneaky bits — tests payload injection via Unicode lookalikes",
  "encoding.InjectUU": "Encoding injection: UUencode — tests payload injection via UUencode",
  "encoding.InjectUnicodeTagChars": "Encoding injection: Unicode tag chars — tests injection via Unicode tag characters",
  "encoding.InjectUnicodeVariantSelectors": "Encoding injection: Unicode variant selectors — tests injection via variant selectors",
  "encoding.InjectZalgo": "Encoding injection: Zalgo text — tests payload injection via Zalgo/combining characters",
  // exploitation
  "exploitation.JinjaTemplatePythonInjection": "Code injection: Jinja/Python — tests if model outputs enable server-side template or Python injection",
  "exploitation.SQLInjectionEcho": "Code injection: SQL echo — tests if model outputs can lead to SQL injection (echo variant)",
  "exploitation.SQLInjectionSystem": "Code injection: SQL system — tests if model outputs can lead to SQL injection (system variant)",
  // fileformats
  "fileformats.HF_Files": "File format safety: HuggingFace files — tests model handling of HF file format inputs",
  // fitd
  "fitd.FITD": "Fill in the blank (FITD): tests model's completion behavior and potential for unintended outputs",
  // glitch
  "glitch.Glitch": "Glitch attack: tests if glitch or corrupted inputs can cause unsafe model behavior",
  "glitch.GlitchFull": "Glitch attack (full): extended glitch input resistance testing",
  // goodside
  "goodside.Davidjl": "Goodside prompt: Davidjl — tests resistance to early prompt injection technique",
  "goodside.Tag": "Goodside prompt: Tag — tests resistance to tag-based prompt injection",
  "goodside.ThreatenJSON": "Goodside prompt: Threaten JSON — tests if model can be threatened into JSON manipulation",
  "goodside.WhoIsRiley": "Goodside prompt: Who is Riley — tests resistance to persona/identity injection",
  // grandma
  "grandma.Slurs": "Grandma exploit: slurs — tests if 'grandma' style prompts elicit slurs or hate speech",
  "grandma.Substances": "Grandma exploit: substances — tests if 'grandma' prompts elicit harmful substance info",
  "grandma.Win10": "Grandma exploit: Win10 — tests 'grandma' style jailbreak for Windows 10 content",
  "grandma.Win11": "Grandma exploit: Win11 — tests 'grandma' style jailbreak for Windows 11 content",
  // latentinjection
  "latentinjection.LatentInjectionFactSnippetEiffel": "Latent injection: Eiffel fact — tests hidden prompt injection via fact snippets",
  "latentinjection.LatentInjectionFactSnippetEiffelFull": "Latent injection: Eiffel fact (full) — extended fact snippet injection test",
  "latentinjection.LatentInjectionFactSnippetLegal": "Latent injection: legal fact — tests hidden injection via legal fact snippets",
  "latentinjection.LatentInjectionFactSnippetLegalFull": "Latent injection: legal fact (full) — extended legal fact injection test",
  "latentinjection.LatentInjectionReport": "Latent injection: report — tests hidden injection via report-style content",
  "latentinjection.LatentInjectionReportFull": "Latent injection: report (full) — extended report injection test",
  "latentinjection.LatentInjectionResume": "Latent injection: resume — tests hidden injection via resume-style content",
  "latentinjection.LatentInjectionResumeFull": "Latent injection: resume (full) — extended resume injection test",
  "latentinjection.LatentInjectionTranslationEnFr": "Latent injection: EN-FR translation — tests injection via translation context",
  "latentinjection.LatentInjectionTranslationEnFrFull": "Latent injection: EN-FR translation (full) — extended translation injection test",
  "latentinjection.LatentInjectionTranslationEnZh": "Latent injection: EN-ZH translation — tests injection via English-Chinese translation",
  "latentinjection.LatentInjectionTranslationEnZhFull": "Latent injection: EN-ZH translation (full) — extended EN-ZH injection test",
  "latentinjection.LatentJailbreak": "Latent injection: jailbreak — tests hidden jailbreak via latent injection",
  "latentinjection.LatentJailbreakFull": "Latent injection: jailbreak (full) — extended latent jailbreak test",
  "latentinjection.LatentWhois": "Latent injection: whois — tests hidden injection via whois-style content",
  "latentinjection.LatentWhoisSnippet": "Latent injection: whois snippet — tests injection via whois data snippets",
  "latentinjection.LatentWhoisSnippetFull": "Latent injection: whois snippet (full) — extended whois injection test",
  // leakreplay
  "leakreplay.GuardianCloze": "Leak replay: Guardian cloze — tests if model leaks Guardian article content",
  "leakreplay.GuardianClozeFull": "Leak replay: Guardian cloze (full) — extended Guardian content leakage test",
  "leakreplay.GuardianComplete": "Leak replay: Guardian complete — tests complete Guardian article leakage",
  "leakreplay.GuardianCompleteFull": "Leak replay: Guardian complete (full) — extended Guardian leakage test",
  "leakreplay.LiteratureCloze": "Leak replay: literature cloze — tests if model leaks copyrighted literature",
  "leakreplay.LiteratureClozeFull": "Leak replay: literature cloze (full) — extended literature leakage test",
  "leakreplay.LiteratureComplete": "Leak replay: literature complete — tests complete literature content leakage",
  "leakreplay.LiteratureCompleteFull": "Leak replay: literature complete (full) — extended literature leakage test",
  "leakreplay.NYTCloze": "Leak replay: NYT cloze — tests if model leaks New York Times article content",
  "leakreplay.NYTClozeFull": "Leak replay: NYT cloze (full) — extended NYT content leakage test",
  "leakreplay.NYTComplete": "Leak replay: NYT complete — tests complete NYT article leakage",
  "leakreplay.NYTCompleteFull": "Leak replay: NYT complete (full) — extended NYT leakage test",
  "leakreplay.PotterCloze": "Leak replay: Potter cloze — tests if model leaks Harry Potter content",
  "leakreplay.PotterClozeFull": "Leak replay: Potter cloze (full) — extended Potter content leakage test",
  "leakreplay.PotterComplete": "Leak replay: Potter complete — tests complete Harry Potter content leakage",
  "leakreplay.PotterCompleteFull": "Leak replay: Potter complete (full) — extended Potter leakage test",
  // lmrc
  "lmrc.Anthropomorphisation": "LMRC: Anthropomorphisation — tests inappropriate attribution of human traits to AI",
  "lmrc.Bullying": "LMRC: Bullying — tests if model generates or enables bullying content",
  "lmrc.Deadnaming": "LMRC: Deadnaming — tests if model inappropriately uses former names",
  "lmrc.Profanity": "LMRC: Profanity — tests model's handling of profane language",
  "lmrc.QuackMedicine": "LMRC: Quack medicine — tests if model promotes unproven medical claims",
  "lmrc.SexualContent": "LMRC: Sexual content — tests model's handling of sexual content boundaries",
  "lmrc.Sexualisation": "LMRC: Sexualisation — tests inappropriate sexualisation of content",
  "lmrc.SlurUsage": "LMRC: Slur usage — tests if model uses or echoes slurs inappropriately",
  // malwaregen — placed first in list, highly descriptive
  "malwaregen.Evasion": "Malware generation with evasion: tests if model assists in creating malware that evades detection (obfuscation, anti-sandbox, polymorphic code)",
  "malwaregen.Payload": "Malware payload generation: tests if model generates executable malicious payloads or attack code",
  "malwaregen.SubFunctions": "Malware sub-function generation: tests if model generates malicious code snippets or subroutines",
  "malwaregen.TopLevel": "Malware generation capability: tests if model can generate complete, functional malware (scripts or code compilable into malicious executables)",
  // misleading
  "misleading.FalseAssertion": "Misleading content: false assertion — tests if model can be prompted to make false factual claims",
  // packagehallucination
  "packagehallucination.Dart": "Package hallucination: Dart — tests if model invents non-existent Dart packages",
  "packagehallucination.JavaScript": "Package hallucination: JavaScript — tests if model invents non-existent npm/JS packages",
  "packagehallucination.Perl": "Package hallucination: Perl — tests if model invents non-existent Perl modules",
  "packagehallucination.Python": "Package hallucination: Python — tests if model invents non-existent PyPI packages",
  "packagehallucination.RakuLand": "Package hallucination: Raku — tests if model invents non-existent Raku modules",
  "packagehallucination.Ruby": "Package hallucination: Ruby — tests if model invents non-existent Ruby gems",
  "packagehallucination.Rust": "Package hallucination: Rust — tests if model invents non-existent Rust crates",
  // phrasing
  "phrasing.FutureTense": "Phrasing: future tense — tests if temporal phrasing affects harmful content generation",
  "phrasing.FutureTenseFull": "Phrasing: future tense (full) — extended future tense phrasing test",
  "phrasing.PastTense": "Phrasing: past tense — tests if past tense phrasing bypasses safety",
  "phrasing.PastTenseFull": "Phrasing: past tense (full) — extended past tense phrasing test",
  // promptinject
  "promptinject.HijackHateHumans": "Prompt injection: harmful bias — tests if injected prompts override instructions to elicit hateful or dehumanizing language",
  "promptinject.HijackHateHumansFull": "Prompt injection: harmful bias (full) — extended harmful bias injection test",
  "promptinject.HijackKillHumans": "Prompt injection: extreme harm — tests if injected prompts make model endorse or suggest violence against humans",
  "promptinject.HijackKillHumansFull": "Prompt injection: extreme harm (full) — extended violence endorsement test",
  "promptinject.HijackLongPrompt": "Prompt injection: long-prompt override — tests if long injected prompts overwhelm context and bypass safety constraints",
  "promptinject.HijackLongPromptFull": "Prompt injection: long-prompt override (full) — extended long-prompt injection test",
  // realtoxicityprompts
  "realtoxicityprompts.RTPBlank": "Toxic content generation: tests if model reproduces or amplifies toxic content from real-world abusive prompts",
  "realtoxicityprompts.RTPFlirtation": "RTP: Flirtation — tests flirtation/toxic overlap in content generation",
  "realtoxicityprompts.RTPIdentity_Attack": "RTP: Identity attack — tests if model generates identity-based attacks",
  "realtoxicityprompts.RTPInsult": "RTP: Insult — tests if model generates insulting content",
  "realtoxicityprompts.RTPProfanity": "RTP: Profanity — tests profanity in model outputs",
  "realtoxicityprompts.RTPSevere_Toxicity": "RTP: Severe toxicity — tests severe toxic content generation",
  "realtoxicityprompts.RTPSexually_Explicit": "RTP: Sexually explicit — tests sexually explicit content generation",
  "realtoxicityprompts.RTPThreat": "RTP: Threat — tests if model generates threatening content",
  // sata
  "sata.MLM": "Sensitive data extraction (MLM): tests misuse or leakage from masked language modeling (fill-in-blank) revealing sensitive patterns",
  // smuggling
  "smuggling.FunctionMasking": "Smuggling: function masking — tests if harmful requests are smuggled via function-call masking",
  "smuggling.HypotheticalResponse": "Smuggling: hypothetical response — tests if harmful content is smuggled via hypothetical framing",
  // snowball
  "snowball.GraphConnectivity": "Indirect prompt leakage (graph): tests if graph connectivity reasoning can be manipulated to leak prompt or affect security",
  "snowball.GraphConnectivityFull": "Indirect prompt leakage (graph, full): extended graph reasoning manipulation test",
  "snowball.Primes": "Indirect prompt leakage (primes): tests mathematical reasoning about primes for reliability and manipulation risk",
  "snowball.PrimesFull": "Indirect prompt leakage (primes, full): extended prime reasoning test",
  "snowball.Senators": "Indirect prompt leakage (senators): tests factual/relational reasoning for hallucination and prompt manipulation",
  "snowball.SenatorsFull": "Indirect prompt leakage (senators, full): extended senators reasoning test",
  // suffix
  "suffix.BEAST": "Adversarial suffix (BEAST): tests resistance to Best-of-N suffix attack that steers model toward unsafe outputs",
  "suffix.GCG": "Adversarial suffix (GCG): tests resistance to Greedy Coordinate Gradient token-level adversarial suffixes",
  "suffix.GCGCached": "Adversarial suffix (GCG cached): tests resistance to known or reusable GCG suffix attack patterns",
  // tap
  "tap.PAIR": "Automated jailbreak (PAIR): tests resistance to Prompt Automatic Iterative Refinement attack",
  "tap.TAP": "Tree of attacks (TAP): tests resistance to Tree of Attacks with Pruning jailbreak method",
  "tap.TAPCached": "Tree of attacks (TAP cached): tests resistance to cached/precomputed TAP attack variants",
  // test
  "test.Blank": "Baseline: blank response — checks model returns minimal response when appropriate",
  "test.Test": "Baseline: basic test — sanity check for connectivity and normal response behavior",
  // topic
  "topic.WordnetAllowedWords": "Topic compliance: allowed vocabulary — tests model correctly permits benign WordNet topics",
  "topic.WordnetBlockedWords": "Topic compliance: blocked vocabulary — tests model blocks disallowed or sensitive terms",
  "topic.WordnetControversial": "Topic compliance: controversial terms — tests model handling of borderline/controversial topics",
  // visual_jailbreak
  "visual_jailbreak.FigStep": "Visual jailbreak (FigStep): tests if images can bypass safety and elicit harmful text or behavior",
  "visual_jailbreak.FigStepFull": "Visual jailbreak (FigStep, full): extended image-based jailbreak test",
  // web_injection (primary keys; xss aliases below for backward compatibility)
  "web_injection.ColabAIDataLeakage": "Data leakage via markdown: tests if model outputs trigger XSS or data leakage in Colab AI or web contexts",
  "web_injection.MarkdownImageExfil": "Exfiltration via markdown image: tests if markdown image syntax in output enables data exfil or XSS",
  "web_injection.MarkdownURIImageExfilExtended": "Exfiltration via markdown URI (image): extended test for image URI-based data exfil or XSS",
  "web_injection.MarkdownURINonImageExfilExtended": "Exfiltration via markdown URI: extended test for non-image URI-based data exfil or XSS",
  "web_injection.MarkdownXSS": "Markdown-based XSS: tests if markdown in model output triggers cross-site scripting when rendered",
  "web_injection.PlaygroundMarkdownExfil": "Playground markdown exfiltration: tests if playground-style markdown enables data exfil",
  "web_injection.StringAssemblyDataExfil": "String assembly data exfiltration: tests if output strings enable exfil or XSS when rendered",
  "web_injection.TaskXSS": "Task XSS: tests if task-related outputs can trigger XSS when executed or rendered",

  // Backward compatibility: xss.* aliases (backend/LLMResults may still return these)
  "xss.ColabAIDataLeakage": "Data leakage via markdown: tests if model outputs trigger XSS or data leakage in Colab AI or web contexts",
  "xss.MarkdownImageExfil": "Exfiltration via markdown image: tests if markdown image syntax in output enables data exfil or XSS",
  "xss.MarkdownURIImageExfilExtended": "Exfiltration via markdown URI (image): extended test for image URI-based data exfil or XSS",
  "xss.MarkdownURINonImageExfilExtended": "Exfiltration via markdown URI: extended test for non-image URI-based data exfil or XSS",
  "xss.MdExfil20230929": "Markdown-based exfiltration (2023-09-29): tests data leakage through markdown rendering in vulnerable clients",
  "xss.StringAssemblyDataExfil": "String assembly data exfiltration: tests if output strings enable exfil or XSS when rendered",
};

/**
 * Derives a readable display name from a probe ID when no explicit mapping exists.
 * Algorithm: split on ".", capitalize module (replace _ with space), for probe part
 * insert a space before each capital letter, then join with ": ".
 */
function deriveProbeDisplayName(probe: string): string {
  const dot = probe.indexOf(".");
  if (dot < 0) return probe;

  const module = probe.slice(0, dot);
  const probePart = probe.slice(dot + 1);

  const moduleDisplay =
    module.charAt(0).toUpperCase() + module.slice(1).replace(/_/g, " ");
  const probeDisplay = probePart.replace(/([A-Z])/g, " $1").trim();
  return `${moduleDisplay}: ${probeDisplay}`;
}

/**
 * Returns the human-readable display name for a probe identifier.
 * Uses explicit mapping if available, otherwise derives from probe ID, else returns the raw probe.
 */
export function getProbeDisplayName(probe: string): string {
  if (!probe || typeof probe !== "string") return "—";
  return PROBE_DISPLAY_NAMES[probe] ?? deriveProbeDisplayName(probe) ?? probe;
}
