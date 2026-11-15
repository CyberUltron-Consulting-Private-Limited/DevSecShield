/**
 * #59: the host CAs a Linux source trusts under "Host certificates" (host_key_policy host_ca): the CA's OpenSSH public
 * key line, one per line, as its .pub file holds it. The API parses each key again at save (backend
 * kinds.check_host_ca_keys); this says early what it will refuse. null when the lines are fine.
 */
export const MAX_HOST_CAS = 20;
const KEY_TYPES = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))$/;

export function hostCaLines(text: string): string[] {
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
}

export function hostCaKeysProblem(text: string): string | null {
  const lines = hostCaLines(text);
  if (lines.length === 0) return "Paste the public key of at least one host CA (the CA that signs the servers' host certificates)";
  if (lines.length > MAX_HOST_CAS) return `At most ${MAX_HOST_CAS} host CAs`;
  for (const [i, line] of lines.entries()) {
    const where = `Line ${i + 1}`;
    if (line.includes("PRIVATE KEY")) return `${where} is a private key; paste the CA's public key (its .pub file)`;
    if (line.startsWith("@")) return `${where} is a known_hosts line; paste only the CA's public key, without @cert-authority and host patterns`;
    const [type, blob] = line.split(/\s+/);
    if (type.includes("-cert-v01@openssh.com")) return `${where} is a certificate; paste the public key of the CA that signs the host certificates`;
    if (!KEY_TYPES.test(type) || !blob || !/^[A-Za-z0-9+/]+={0,2}$/.test(blob)) return `${where} is not an SSH public key (as in the CA's .pub file)`;
  }
  return null;
}
