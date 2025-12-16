"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type LLMScanCreateData = {
    model_type: string;
    model_name: string;
    probes: string[];
    api_key: string;
    generations: number;
    headers: string;
    request_template: string;
    response_json_field: string;
    model_uri: string;
}

type ModelChoicePickerProps = {
    creationData: LLMScanCreateData;
    updateCreationData: (field: keyof LLMScanCreateData, value: any) => void;
}

const openaiModels = [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "gpt-4",
    "gpt-3.5-turbo",
    "gpt-3.5-turbo-16k"
];

const anthropicModels = [
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307"
];

const geminiModels = [
    "gemini-1.5-pro",
    "gemini-1.5-flash",
    "gemini-pro"
];

export default function ModelChoicePicker({ creationData, updateCreationData }: ModelChoicePickerProps) {
    const getModels = () => {
        switch (creationData.model_type) {
            case "openai":
                return openaiModels;
            case "anthropic":
                return anthropicModels;
            case "gemini":
                return geminiModels;
            default:
                return [];
        }
    };

    const models = getModels();

    return (
        <Select
            value={creationData.model_name}
            onValueChange={(value) => updateCreationData("model_name", value)}
        >
            <SelectTrigger className="w-full cursor-pointer bg-zinc-700 border-zinc-600 text-white">
                <SelectValue placeholder="Select model" />
            </SelectTrigger>
            <SelectContent className="bg-zinc-800 border-zinc-700">
                {models.map((model) => (
                    <SelectItem key={model} value={model} className="text-white hover:bg-zinc-700">
                        {model}
                    </SelectItem>
                ))}
            </SelectContent>
        </Select>
    );
}

