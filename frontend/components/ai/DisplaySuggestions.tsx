'use client';

import { Card, CardContent } from '@/components/ui/card';
import { AlertTriangle, Calendar, Shield, Activity, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Alert } from '../ui/alert';

interface SuggestionCard {
  icon: React.ReactNode;
  title: string;
  description: string;
  onClick: () => void;
}

interface DisplaySuggestionsProps {
  onSuggestionClick?: (suggestion: string) => void;
  className?: string;
}

export function DisplaySuggestions({ onSuggestionClick, className }: DisplaySuggestionsProps) {
  const suggestions: SuggestionCard[] = [
    {
      icon: <AlertTriangle className="h-4 w-4 text-blue-500" />,
      title: 'List the top 10 vulnerabilities found',
      description: 'Displays top 10 discovered vulnerabilities',
      onClick: () => onSuggestionClick?.('List the top 10 vulnerabilities found'),
    },
    {
      icon: <AlertCircle className="h-4 w-4 text-blue-500" />,
      title: 'List the vulnerabilities found that map to recentcritical CVEs',
      description: 'Shows vulnerabilities that map to recent critical CVEs',
      onClick: () => onSuggestionClick?.('List the vulnerabilities found that map to recentcritical CVEs'),
    },
    {
      icon: <Shield className="h-4 w-4 text-blue-500" />,
      title: 'List the vulnerabilities found that map to recent medium CVEs',
      description: 'Shows vulnerabilities that map to recent medium CVEs',
      onClick: () => onSuggestionClick?.('List the vulnerabilities found that map to recent medium CVEs'),
    },
    {
      icon: <Activity className="h-4 w-4 text-blue-500" />,
      title: 'List the vulnerabilities found that map to recent low CVEs',
      description: 'Shows vulnerabilities that map to recent low CVEs',
      onClick: () => onSuggestionClick?.('List the vulnerabilities found that map to recent low CVEs'),
    },
  ];

  return (
    <div className={cn('grid grid-cols-2 gap-2 p-2 bg-background/95 backdrop-blur-sm rounded-lg border shadow-lg', className)}>
      {suggestions.map((suggestion, index) => (
        <Card
          key={index}
          onClick={suggestion.onClick}
          className="cursor-pointer transition-all hover:shadow-md hover:border-blue-300 dark:hover:border-blue-600 bg-white dark:bg-zinc-900"
        >
          <CardContent className="flex flex-col gap-1 p-2">
            <div className="flex items-center gap-2">
              {suggestion.icon}
              <h3 className="font-semibold text-xs text-zinc-900 dark:text-white leading-tight">
                {suggestion.title}
              </h3>
            </div>
            <p className="text-xs text-zinc-600 dark:text-zinc-400 ml-6 leading-tight">
              {suggestion.description}
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

