"""
Binary/directory scanner using cbomkit-theia subprocess.
Wraps the Go binary CLI tool (or Docker image) for certificate, key, secret,
and config detection.
"""

import json
import os
import subprocess
import shutil
from rich.console import Console

console = Console()

# Docker image for cbomkit-theia when the Go binary is not installed locally.
CBOMKIT_DOCKER_IMAGE = "ghcr.io/cbomkit/cbomkit-theia:latest"


def _docker_available() -> bool:
    """Return True if docker CLI is on PATH."""
    return shutil.which("docker") is not None


def is_cbomkit_theia_available() -> bool:
    """Check if cbomkit-theia is available (binary on PATH or Docker)."""
    if shutil.which("cbomkit-theia") is not None:
        return True
    if _docker_available():
        return True
    return False


def _run_via_binary(directory: str) -> subprocess.CompletedProcess:
    """Run cbomkit-theia Go binary directly."""
    cmd = ["cbomkit-theia", "dir", directory]
    console.print(f"Running cbomkit-theia (binary): {' '.join(cmd)}", style="dim cyan")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=600)


def _run_via_docker(directory: str) -> subprocess.CompletedProcess:
    """Run cbomkit-theia via Docker container with the directory bind-mounted."""
    abs_dir = os.path.abspath(directory)
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{abs_dir}:/scan:ro",
        CBOMKIT_DOCKER_IMAGE,
        "dir", "/scan",
    ]
    console.print(f"Running cbomkit-theia (Docker): {' '.join(cmd)}", style="dim cyan")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=900)


def run_cbomkit_theia(directory: str) -> dict | None:
    """
    Run cbomkit-theia on a directory to detect certificates, keys, secrets,
    and crypto configs.  Falls back to Docker when the Go binary is not on PATH.
    
    Returns:
        Parsed JSON output from cbomkit-theia, or None if unavailable / fails.
    """
    use_binary = shutil.which("cbomkit-theia") is not None
    use_docker = (not use_binary) and _docker_available()

    if not use_binary and not use_docker:
        console.print(
            "cbomkit-theia is not installed and Docker is not available, "
            "skipping binary scanning",
            style="bold yellow",
        )
        return None

    try:
        result = _run_via_binary(directory) if use_binary else _run_via_docker(directory)

        if result.returncode != 0:
            console.print(f"cbomkit-theia returned non-zero exit code: {result.returncode}", style="bold yellow")
            console.print(f"stderr: {result.stderr[:500]}", style="dim red")
            if not result.stdout.strip():
                return None
            # cbomkit-theia may exit non-zero on partial errors but still produce
            # valid JSON.  Validate JSON before trusting it.
            console.print("cbomkit-theia produced output despite non-zero exit – attempting to parse", style="dim yellow")

        output = json.loads(result.stdout)
        if not isinstance(output, dict):
            console.print("cbomkit-theia output is not a JSON object, discarding", style="bold yellow")
            return None

        # "components" may be missing OR explicitly null when no crypto is found.
        # Coerce both to [] so downstream len()/iteration never sees None.
        components = output.get("components") or []
        output["components"] = components
        if not components:
            console.print(
                "cbomkit-theia returned zero usable cryptographic components "
                "(null/empty 'components'); binary scan produced no crypto assets",
                style="bold yellow",
            )
        else:
            console.print(f"cbomkit-theia found {len(components)} cryptographic components", style="bold cyan")
        return output

    except subprocess.TimeoutExpired:
        console.print("cbomkit-theia timed out", style="bold red")
        return None
    except json.JSONDecodeError as e:
        console.print(f"cbomkit-theia output is not valid JSON: {e}", style="bold red")
        return None
    except Exception as e:
        console.print(f"Error running cbomkit-theia: {e}", style="bold red")
        return None


def parse_theia_components(theia_output: dict) -> list[dict]:
    """
    Parse cbomkit-theia CycloneDX output into normalized crypto asset dicts.
    
    Args:
        theia_output: Raw JSON output from cbomkit-theia (CycloneDX format).
    
    Returns:
        List of normalized crypto asset dictionaries.
    """
    if not theia_output:
        return []

    assets = []
    # "components" may be missing OR explicitly null (no crypto found) -> treat as [].
    components = theia_output.get("components") or []
    if not components:
        console.print(
            "cbomkit-theia output has zero usable components; no crypto assets to parse",
            style="bold yellow",
        )
        return []

    for component in components:
        comp_type = component.get("type", "")
        name = component.get("name", "Unknown")
        
        # Determine crypto asset type from CycloneDX component type
        crypto_props = component.get("cryptoProperties", {})
        asset_type = crypto_props.get("assetType", "").lower() if crypto_props else ""
        
        # Map CycloneDX assetType to our enum
        type_mapping = {
            "algorithm": _classify_algorithm_type(name),
            "certificate": "certificate",
            "related-crypto-material": "key",
            "protocol": "protocol",
        }
        
        algo_type = type_mapping.get(asset_type, "certificate")
        
        # Extract properties
        properties = {}
        for prop in component.get("properties", []):
            properties[prop.get("name", "")] = prop.get("value", "")
        
        # Determine strength 
        oid = crypto_props.get("oid", "")
        key_size = _extract_key_size(crypto_props)
        quantum_safe = _is_quantum_safe(name)
        strength = _classify_strength(name, key_size)
        
        # Determine location from evidence/occurrences
        location = ""
        evidence = component.get("evidence", {})
        occurrences = evidence.get("occurrences", [])
        if occurrences:
            location = occurrences[0].get("location", "")
        
        asset = {
            "algorithm_name": name,
            "algorithm_type": algo_type,
            "crypto_strength": strength,
            "key_size": key_size,
            "quantum_safe": quantum_safe,
            "location": location or properties.get("file", "binary/config"),
            "snippet": f"Detected by cbomkit-theia: {name} (OID: {oid})" if oid else f"Detected by cbomkit-theia: {name}",
            "source": "cbomkit-theia",
        }
        assets.append(asset)
    
    console.print(f"Parsed {len(assets)} crypto assets from cbomkit-theia output", style="bold cyan")
    return assets


def _classify_algorithm_type(name: str) -> str:
    """Classify algorithm type from its name."""
    name_lower = name.lower()
    if any(h in name_lower for h in ["sha", "md5", "md4", "blake", "ripemd"]):
        return "hash"
    if any(s in name_lower for s in ["aes", "des", "chacha", "blowfish", "rc4", "rc2", "camellia"]):
        return "symmetric_cipher"
    if any(a in name_lower for a in ["rsa", "ecdsa", "ed25519", "dh", "ecdh", "dsa", "kyber", "dilithium"]):
        return "asymmetric_cipher"
    if any(k in name_lower for k in ["pbkdf", "scrypt", "argon", "hkdf", "bcrypt"]):
        return "key_derivation"
    if any(m in name_lower for m in ["hmac", "cmac", "poly1305", "gmac"]):
        return "mac"
    if any(p in name_lower for p in ["tls", "ssl", "dtls", "ssh"]):
        return "protocol"
    return "symmetric_cipher"


def _extract_key_size(crypto_props: dict) -> int | None:
    """Extract key size from CycloneDX crypto properties."""
    if not crypto_props:
        return None
    
    # Check algorithmProperties
    algo_props = crypto_props.get("algorithmProperties", {})
    if algo_props:
        key_length = algo_props.get("parameterSetIdentifier", "")
        if key_length and key_length.isdigit():
            return int(key_length)
    
    # Check relatedCryptoMaterialProperties
    material_props = crypto_props.get("relatedCryptoMaterialProperties", {})
    if material_props:
        size = material_props.get("size")
        if size and isinstance(size, (int, float)):
            return int(size)
    
    return None


def _is_quantum_safe(name: str) -> bool:
    """Check if algorithm is quantum-safe."""
    name_lower = name.lower()
    pqc_names = ["kyber", "dilithium", "sphincs", "falcon", "ntru", "saber", "frodo", "bike", "hqc", "sha3"]
    return any(pqc in name_lower for pqc in pqc_names)


def _classify_strength(name: str, key_size: int | None) -> str:
    """Classify crypto strength."""
    name_lower = name.lower()
    
    # Quantum safe
    if _is_quantum_safe(name):
        return "quantum_safe"
    
    # Weak
    weak_names = ["md5", "md4", "sha1", "sha-1", "des", "rc2", "rc4", "sslv3", "tls1.0", "tls1.1"]
    if any(w in name_lower for w in weak_names):
        return "weak"
    
    # Moderate
    moderate_names = ["3des", "triple", "blowfish", "dsa"]
    if any(m in name_lower for m in moderate_names):
        return "moderate"
    if key_size and key_size < 2048 and "rsa" in name_lower:
        return "weak" if key_size < 1024 else "moderate"
    
    # Strong (default for known algorithms)
    return "strong"
