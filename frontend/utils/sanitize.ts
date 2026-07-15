/**
 * XSS Sanitization Utility
 * 
 * Uses DOMPurify to sanitize HTML/Markdown content before rendering.
 * This prevents XSS attacks from malicious content in user messages,
 * AI responses, scan results, or any other untrusted source.
 */
import DOMPurify from 'isomorphic-dompurify';

/**
 * Sanitize HTML content, removing any potential XSS vectors.
 * Allows safe HTML elements while stripping dangerous ones.
 */
export function sanitizeHtml(dirty: string): string {
  if (!dirty) return '';
  
  return DOMPurify.sanitize(dirty, {
    // Allow common HTML elements for markdown rendering
    ALLOWED_TAGS: [
      'p', 'br', 'span', 'div',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'strong', 'b', 'em', 'i', 'u', 's', 'del',
      'ul', 'ol', 'li',
      'a', 'code', 'pre',
      'blockquote', 'hr',
      'table', 'thead', 'tbody', 'tr', 'th', 'td',
      'img', 'figure', 'figcaption',
      'details', 'summary',
      'mark', 'sub', 'sup',
    ],
    // Allow safe attributes
    ALLOWED_ATTR: [
      'href', 'target', 'rel', 'title', 'alt',
      'src', 'width', 'height',
      'class', 'id',
      'colspan', 'rowspan',
      'open',
    ],
    // Force all links to open in new tab with noopener
    ADD_ATTR: ['target', 'rel'],
    // Additional security
    FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'input', 'textarea', 'select', 'button'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur'],
    // Allow data URIs only for images (with restrictions)
    ALLOW_DATA_ATTR: false,
    // Return type
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    RETURN_TRUSTED_TYPE: false,
  });
}

/**
 * Sanitize markdown content before passing to ReactMarkdown.
 * This provides defense-in-depth even though ReactMarkdown has some built-in protections.
 */
export function sanitizeMarkdown(dirty: string): string {
  if (!dirty) return '';
  
  // Remove potentially dangerous patterns before markdown processing
  let cleaned = dirty;
  
  // Remove javascript: URLs
  cleaned = cleaned.replace(/javascript:/gi, '');
  
  // Remove data: URLs except for safe image formats
  cleaned = cleaned.replace(/data:(?!image\/(png|jpeg|jpg|gif|webp|svg\+xml))[^)'">\s]+/gi, '');
  
  // Remove event handlers in any format
  cleaned = cleaned.replace(/on\w+\s*=/gi, '');
  
  // Remove HTML comments that might contain script
  cleaned = cleaned.replace(/<!--[\s\S]*?-->/g, '');
  
  // Remove <script>, <style>, <iframe> etc even if not well-formed
  cleaned = cleaned.replace(/<\s*(script|style|iframe|form|input|textarea|select|button)[^>]*>[\s\S]*?<\/\s*\1\s*>/gi, '');
  cleaned = cleaned.replace(/<\s*(script|style|iframe|form|input|textarea|select|button)[^>]*\/?>/gi, '');
  
  return cleaned;
}

/**
 * Sanitize plain text content (strip all HTML).
 */
export function sanitizePlainText(dirty: string): string {
  if (!dirty) return '';
  
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [], // No HTML tags allowed
    ALLOWED_ATTR: [],
  });
}

/**
 * Sanitize URL to prevent javascript: and data: attacks.
 */
export function sanitizeUrl(url: string): string {
  if (!url) return '';
  
  const trimmedUrl = url.trim().toLowerCase();
  
  // Block javascript: URLs
  if (trimmedUrl.startsWith('javascript:')) {
    return '';
  }
  
  // Block data: URLs except for safe image formats
  if (trimmedUrl.startsWith('data:') && !trimmedUrl.startsWith('data:image/')) {
    return '';
  }
  
  // Block vbscript: URLs
  if (trimmedUrl.startsWith('vbscript:')) {
    return '';
  }
  
  return url;
}

/**
 * Hook to add rel="noopener noreferrer" to all sanitized links.
 * Call this once at app initialization.
 */
export function configureSanitizer(): void {
  DOMPurify.addHook('afterSanitizeAttributes', (node: Element) => {
    // Set all external links to open in new tab safely
    if (node.tagName === 'A') {
      const href = node.getAttribute('href');
      if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
        node.setAttribute('target', '_blank');
        node.setAttribute('rel', 'noopener noreferrer');
      }
    }
    
    // Validate image sources
    if (node.tagName === 'IMG') {
      const src = node.getAttribute('src');
      if (src) {
        const sanitizedSrc = sanitizeUrl(src);
        if (sanitizedSrc !== src) {
          node.setAttribute('src', sanitizedSrc);
        }
      }
    }
  });
}

export default {
  sanitizeHtml,
  sanitizeMarkdown,
  sanitizePlainText,
  sanitizeUrl,
  configureSanitizer,
};
