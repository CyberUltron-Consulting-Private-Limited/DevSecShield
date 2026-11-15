/**
 * #61: an SSH CA whose key the customer keeps on the scan node. The form takes only its public key (the API checks
 * it again at save, sshca/registry._node_public_key); null when the line is fine.
 */
export function nodeCaKeyProblem(text: string): string | null {
  const line = text.trim();
  if (!line) return "Paste the public key of the CA key installed on the scan node (its .pub file)";
  if (line.includes("PRIVATE KEY")) return "This is a private key: it stays on the scan node. Paste its public key (.pub file)";
  const [type, blob] = line.split(/\s+/);
  if (type.includes("-cert-v01@openssh.com")) return "Paste the CA's public key, not a certificate";
  if (type !== "ssh-ed25519" && type !== "ecdsa-sha2-nistp256") return "The scan node signs with Ed25519 or ECDSA P-256 CA keys only";
  if (!blob || !/^[A-Za-z0-9+/]+={0,2}$/.test(blob)) return "This is not an SSH public key line";
  return null;
}
