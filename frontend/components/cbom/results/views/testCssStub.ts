// Tests only: lets Node require a component that imports a stylesheet (React Flow's CSS) by loading .css as nothing.
// Import it before the component under test.
import Module from "node:module";

(Module as unknown as { _extensions: Record<string, () => void> })._extensions[".css"] = () => undefined;
