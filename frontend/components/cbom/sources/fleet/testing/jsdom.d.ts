// The part of jsdom the render tests use (jsdom ships no types and @types/jsdom is not installed).
declare module "jsdom" {
  export class JSDOM {
    constructor(html?: string, options?: { url?: string; pretendToBeVisual?: boolean });
    readonly window: Window & typeof globalThis;
  }
}
