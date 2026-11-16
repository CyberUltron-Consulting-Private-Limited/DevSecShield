/**
 * (i) tip text of the "cbsrc-cloud" area (ids: cbsrc.cloud.*, cbsrc.aws.*, cbsrc.azure.*, cbsrc.gcp.*, cbsrc.idp.*, cbsrc.ca.*, cbsrc.cert.*, cbsrc.ct.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources: Cloud & Identity (components/cbom/sources/CloudIdentityTab.tsx)
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:75-89,520 — AWS by role, Azure by app registration, Google Cloud by service account
  "cbsrc.cloud.connect": {
    what: "Connect an AWS account (ZeroShield assumes a read-only role with your external ID, no keys exchanged), an Azure subscription (Key Vault metadata through an app registration) or Google Cloud (KMS, CA Service and Secret Manager metadata through a service account).",
    why: "Cloud KMS keys, certificates and secrets are a large part of the crypto estate and are invisible to network scans.",
    example: "AWS account 111122223333 with the ZeroShieldCBOMReader role in eu-west-1 and ap-south-1.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:579-592 — the checks of the last validation
  "cbsrc.cloud.validation": {
    what: "The checks of the last validation of the selected account: each read-only call ZeroShield tried and whether it passed, failed, was skipped or hit an error.",
    why: "An account that fails a check is collected only partly, so fix the role or permission it names.",
    example: "kms:ListKeys in ap-south-1 · Fail: the role is missing kms:ListKeys.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:596-600 — 4 credits per account per run
  "cbsrc.cloud.list": {
    what: "The cloud accounts of this team. Accounts that pass validation are scanned read-only from ZeroShield's cloud, 4 credits per account per run.",
    why: "Only accounts listed here are part of a run's cloud inventory.",
    example: "payments-prod · AWS · One account · 2 regions · Valid.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:624 — the provider's account or tenant
  "cbsrc.cloud.col.account": {
    what: "The cloud provider and the account, subscription or project identifier.",
    why: "Tells you where to make a fix in the provider's console.",
    example: "AWS 111122223333.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1115-1125 — one account or a whole AWS Organization
  "cbsrc.cloud.col.scope": {
    what: "What the connection covers: one account, or every member account of an AWS Organization through a StackSet.",
    why: "An Organization connection picks up new member accounts without another setup.",
    example: "Whole AWS Organization · 37 accounts.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1259-1266 — regions read in each run
  "cbsrc.cloud.col.regions": {
    what: "For an AWS account, how many regions are read in each run; resources in other regions are not inventoried. A dash for Azure and Google Cloud.",
    why: "Keys and certificates in a forgotten region are a common blind spot.",
    example: "2: eu-west-1 and ap-south-1.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:628 — time of the last validation
  "cbsrc.cloud.col.validated": {
    what: "When the account was last validated (ZeroShield tried each read-only call), or Never.",
    why: "A role changed since then may make the next run fail.",
    example: "12 Nov 2026, 10:42 am IST.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:143-149, frontend/components/cbom/sources/CloudIdentityTab.tsx:629 — result of the last validation
  "cbsrc.cloud.col.status": {
    what: "The result of the last validation: Not tested, Testing, Passed (every check passed), Partly ready (some checks failed), Failed or Could not test. Hover the badge for its summary.",
    why: "Only valid accounts are scanned fully in a run.",
    example: "Partly ready: KMS passed, ACM was denied.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:705 — CAs, CLM tools and your domains
  "cbsrc.cloud.certificates": {
    what: "Where your certificates come from: certificate authorities and CLM tools you connect, and the domains you own (searched in Certificate Transparency logs where available).",
    why: "Certificates issued outside your managed CAs are the ones that expire unnoticed.",
    example: "AD CS through node-dc1, and bank.in searched in CT logs.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:100-111,714, frontend/components/cbom/sources/CloudIdentityTab.tsx:714, backend/utilities/cbom_sources/kinds.py:605-618 — AD CS, Vault and EJBCA by a scan node; AWS Private CA by its AWS account; CLM tools not collected
  "cbsrc.cloud.cas": {
    what: "Microsoft AD CS, HashiCorp Vault PKI and EJBCA are read by a scan node inside your network. AWS Private CA is read by the connected AWS account it names. Venafi, Keyfactor, DigiCert, Sectigo and other CLM tools are not collected: only their name and API address are saved, no key is asked for and nothing is charged.",
    why: "Your CA knows every certificate it issued, including ones on hosts no scan reaches.",
    example: "AD CS on ca01.bank.local, read by node-dc1 over WinRM.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:761, frontend/components/cbom/sources/CloudIdentityTab.tsx:761 — public OIDC and SAML metadata, free
  "cbsrc.cloud.idps": {
    what: "Signing keys and certificates of your identity providers, read by ZeroShield's cloud from each provider's public OIDC and SAML metadata. Free.",
    why: "An IdP signing with RSA-2048 or SHA-1 signs every login; it is a key migration target.",
    example: "Okta at https://bank.okta.com: 2 signing keys, RS256, one expiring in 30 days.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1115-1125 — CloudFormation stack or StackSet
  "cbsrc.aws.scope": {
    what: "One account: create a CloudFormation stack in that account. Whole AWS Organization: deploy a StackSet from the management account to every member account.",
    why: "It decides which template you deploy and which accounts are inventoried.",
    example: "Whole AWS Organization for 37 accounts managed by Control Tower.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1152-1185 — off by default; template parameters follow the switches
  "cbsrc.aws.optional_reads": {
    what: "Extra permissions you may grant the read-only role, off by default. The template's parameters follow these switches; changing one later means updating the stack and validating again.",
    why: "Each adds coverage but also a permission that could, in a misconfigured account, return a secret.",
    example: "Turn on Read Glue connections to see which connections skip TLS.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1153-1168 — kms:Decrypt for Lambda environments; only their shape is kept
  "cbsrc.aws.lambda_cmk": {
    what: "Lets the role decrypt Lambda environment variables so ZeroShield can check them for keys and passwords; only their shape is kept, never the values. Off: each function's environment is listed as not inspected.",
    why: "Hard-coded keys in Lambda environments are a frequent finding.",
    example: "On: a function with DB_PASSWORD set in plain text is flagged.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1170-1183 — TLS enforcement and password storage of each connection
  "cbsrc.aws.glue": {
    what: "Reports whether each Glue connection enforces TLS and where its password is stored. ZeroShield asks with HidePassword and keeps only those settings.",
    why: "If Data Catalog password encryption is off, this permission could return a password in plain text.",
    example: "jdbc-core-banking: TLS not enforced, password in the connection.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:29, frontend/components/cbom/sources/CloudIdentityTab.tsx:1239-1254 — arn:aws:iam::<12 digits>:role/<name>
  "cbsrc.aws.role_arn": {
    what: "The ARN of the read-only role the stack created (the RoleArn output). For an Organization, the role in the management account.",
    why: "ZeroShield assumes this role with your external ID; nothing else gives it access.",
    example: "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1259, frontend/components/cbom/sources/CloudIdentityTab.tsx:1259-1276 — AWS region codes; the first one is used for the test read
  "cbsrc.aws.regions": {
    what: "The AWS regions to read, as region codes; press Enter or Add region after each. The first region is used for the validation read.",
    why: "Resources in regions not listed are not inventoried.",
    example: "ap-south-1 and ap-south-2 for the Mumbai and Hyderabad regions.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1293-1300 — up to 64 characters; blank uses aws-<account id>
  "cbsrc.aws.name": {
    what: "A name for this account, up to 64 characters. Blank uses aws-<account id>.",
    why: "Each asset found records it as its source.",
    example: "payments-prod.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1468-1469 — up to 64 characters
  "cbsrc.azure.name": {
    what: "A name for this Azure connection, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "azure-prod.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:28, frontend/components/cbom/sources/CloudIdentityTab.tsx:1471-1481 — a GUID
  "cbsrc.azure.tenant": {
    what: "The GUID of your Microsoft Entra directory (tenant), from the app registration's Overview page.",
    why: "The app registration signs in to this tenant only.",
    example: "72f988bf-86f1-41af-91ab-2d7cd011db47.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:28, frontend/components/cbom/sources/CloudIdentityTab.tsx:1483-1493 — a GUID
  "cbsrc.azure.client": {
    what: "The GUID of the app registration that the reader script gave Key Vault Reader access.",
    why: "ZeroShield signs in as this app; its roles decide what can be read.",
    example: "0f3c6a2e-1b5d-4c8e-9a7f-2d4e6b8c0a1f.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1496-1508 — client secret or certificate
  "cbsrc.azure.credential": {
    what: "Client secret: from Certificates & secrets in the app registration. Certificate: a PEM certificate with its private key; ZeroShield signs a client assertion with it.",
    why: "A certificate credential never sends a reusable secret over the network.",
    example: "Certificate, with the same certificate uploaded to the app registration.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1512, frontend/components/cbom/sources/CloudIdentityTab.tsx:1511-1520 — encrypted at rest; changing tenant, client ID or credential clears it
  "cbsrc.azure.secret": {
    what: "The client secret, or the PEM certificate with its private key. Encrypted at rest by ZeroShield and never shown again; changing the tenant, client ID or credential type clears it.",
    why: "It is the only credential of the connection; rotate it in Azure and paste the new one here.",
    example: "A client secret value created today, valid for 6 months.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1523-1534 — one GUID per line, optional
  "cbsrc.azure.subs": {
    what: "Optional: the subscriptions to read, one GUID per line. Blank reads every subscription the app can see.",
    why: "Narrowing it keeps a shared app registration from inventorying another unit's subscriptions.",
    example: "11111111-2222-3333-4444-555555555555.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1637-1638 — up to 64 characters
  "cbsrc.gcp.name": {
    what: "A name for this Google Cloud connection, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "gcp-payments.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1640-1650 — numeric; blank lists projects instead
  "cbsrc.gcp.org": {
    what: "The numeric ID of your Google Cloud organization. Leave blank to list the projects below instead.",
    why: "With an organization ID every project under it is read, including new ones.",
    example: "123456789012.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1652-1661 — one per line; needed without an organization ID
  "cbsrc.gcp.projects": {
    what: "The project IDs to read, one per line. Needed when there is no organization ID.",
    why: "Projects not listed are not inventoried.",
    example: "payments-prod and core-banking-dr.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1663-1673 — up to 254 characters
  "cbsrc.gcp.email": {
    what: "The email of the service account that the gcloud script granted the viewer roles to.",
    why: "ZeroShield reads as this account; its roles decide what is visible.",
    example: "zs-cbom@payments-prod.iam.gserviceaccount.com.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1676, frontend/components/cbom/sources/CloudIdentityTab.tsx:1675-1688 — encrypted at rest; changing the service account clears it
  "cbsrc.gcp.key": {
    what: "The JSON key of the service account, pasted or uploaded. Encrypted at rest by ZeroShield and never shown again; changing the service account clears it.",
    why: "Anyone with this key can act as the service account, so it should hold viewer roles only.",
    example: "The .json file from IAM > Service accounts > Keys.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1690-1701 — .json up to 64 KB
  "cbsrc.gcp.key_file": {
    what: "Pick the .json key file instead of pasting it; it fills the key field above. Up to 64 KB.",
    why: "Uploading avoids copy-paste errors in the long key.",
    example: "zs-cbom-payments-prod-3f2a.json.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1831, frontend/components/cbom/sources/CloudIdentityTab.tsx:1830-1836 — up to 200 domains; saved, not yet searched
  "cbsrc.cert.domains": {
    what: "Domains you own, up to 200. They are saved for the certificate collector; ZeroShield does not query Certificate Transparency logs on this deployment yet.",
    why: "CT logs list every public certificate issued for your domains, including ones nobody registered with IT.",
    example: "bank.in and bankonline.co.in.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1945-1954 — searched every run from ZeroShield's cloud; credits per domain
  "cbsrc.ct.discovery": {
    what: "Every run, ZeroShield's cloud searches public Certificate Transparency logs for certificates issued for these domains, including hosts no scan node reaches. Expiring, expired, revoked and weak certificates, and certificates from CAs you have not listed, are flagged. 0.2 credits per domain searched, per run.",
    why: "A certificate issued by a CA you do not use can mean a mis-issuance or a shadow IT service.",
    example: "bank.in: 412 certificates found, 3 from an unexpected CA.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1880, frontend/components/cbom/sources/CloudIdentityTab.tsx:1956-1989 — up to 1,000 domains; a leading *. is dropped
  "cbsrc.ct.domains": {
    what: "The domains to search, up to 1,000. A leading *. is dropped; add each registered domain once.",
    why: "Each domain is one search per run, so list the ones you own.",
    example: "bank.in.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2008-2011 — search subdomains too
  "cbsrc.ct.subdomains": {
    what: "Also search certificates for every subdomain of the listed domains.",
    why: "Most forgotten certificates sit on subdomains such as uat-api.bank.in.",
    example: "On: certificates for netbanking.bank.in are found too.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2013, frontend/components/cbom/sources/CloudIdentityTab.tsx:2013-2015 — up to 50; matched on name, organisation or CN
  "cbsrc.ct.issuers": {
    what: "Optional, up to 50: the CAs you expect. A certificate from any other CA is flagged as unexpected. Matched against the CA's name, organisation or CN: the whole value or its first words (at least 3 characters).",
    why: "Unexpected issuers point at mis-issuance or teams buying certificates outside policy.",
    example: "DigiCert and Let's Encrypt.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2342-2359 — Sectigo or other
  "cbsrc.ca.product": {
    what: "Which certificate product this connection is for, when the row covers several.",
    why: "It names the source in reports.",
    example: "Sectigo Certificate Manager.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2364-2365 — up to 64 characters
  "cbsrc.ca.name": {
    what: "A name for this CA connection, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each certificate found records it as its source.",
    example: "AD CS Mumbai.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2370-2372, backend/utilities/cbom_sources/kinds.py:513 — AD CS, Vault, EJBCA are read through a node
  "cbsrc.ca.node": {
    what: "The scan node, in a segment that reaches the certificate authority, that reads it.",
    why: "Internal CAs are rarely reachable from the internet, so a node inside the network reads them.",
    example: "node-dc1, which reaches ca01.bank.local on 5986.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2391-2392 — reached over WinRM HTTPS (5986)
  "cbsrc.ca.host": {
    what: "The AD CS server's hostname, reached over WinRM HTTPS (5986). Run the Windows setup script from the Servers tab on it first.",
    why: "The CA database lists every certificate it issued, including ones on hosts no scan reaches.",
    example: "ca01.bank.local.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2394-2395, backend/utilities/cbom_sources/kinds.py:27 — up to 64 characters
  "cbsrc.ca.login": {
    what: "A read-only Windows account on the CA server, in Remote Management Users; DOMAIN\\user is accepted.",
    why: "A non-admin account limits what a leaked password can do on your CA.",
    example: "BANK\\svc-zscbom.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2397-2406 — encrypted at rest; changing server, account, CA or node clears it
  "cbsrc.ca.password": {
    what: "The password of the read-only account. Encrypted at rest and sent only to the scan node; changing the server, account, CA or node clears it.",
    why: "Clearing it on change keeps the password from going to a host it was not meant for.",
    example: "The password of svc-zscbom.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2412-2428 — read through a connected AWS account's role
  "cbsrc.ca.aws": {
    what: "The connected AWS account whose read-only role reads AWS Private CA. No new credential is needed.",
    why: "Private CAs in AWS issue internal certificates that never appear in CT logs.",
    example: "payments-prod · 111122223333.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2433-2443 — HTTPS, up to 512 characters
  "cbsrc.ca.api_url": {
    what: "The HTTPS address of this product's API, up to 512 characters. The placeholder shows that product's usual path. The scan node calls only this address.",
    why: "The address is checked when the source is saved, and a stored credential is cleared if the address changes.",
    example: "https://tpp.example.com/vedsdk for Venafi, or https://www.digicert.com/services/v2 for DigiCert.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2580
  "cbsrc.ca.client_id": {
    what: "The Client ID of the API integration in Trust Protection Platform. It is sent with the user name and password when the scan node authorizes.",
    why: "Venafi issues a bearer token for listing certificates only to a registered integration. The password is the stored secret.",
    example: "MyApp, the Client ID shown on the API integration.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2584
  "cbsrc.ca.venafi_login": {
    what: "The Trust Protection Platform user that may read certificates. The scan node sends it as the username when it authorizes.",
    why: "Use an account that can read certificates. The collector requests the certificate scope and does not download private keys.",
    example: "local:admin, or svc-cbom@corp.example.com.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2588
  "cbsrc.ca.venafi_password": {
    what: "The password of that user. Encrypted at rest and sent only to the scan node, which uses it once to authorize.",
    why: "Changing the address, user, client id, CA or node clears it, so it is not sent to a different server.",
    example: "The password of the Venafi user.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2600
  "cbsrc.ca.keyfactor_token": {
    what: "A bearer token for Keyfactor Command. The scan node sends it as Authorization: Bearer, with the header x-keyfactor-requested-with: APIClient.",
    why: "The token is the only credential. It is encrypted at rest and cleared if the address, CA or node changes.",
    example: "The access token from the Keyfactor token endpoint.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2611
  "cbsrc.ca.digicert_key": {
    what: "The CertCentral API key. The scan node sends it as the X-DC-DEVKEY header and does not put it in the address.",
    why: "That header is how CertCentral authenticates a read of orders and a download of the certificate.",
    example: "The key from CertCentral, under Account, API keys.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2622
  "cbsrc.ca.customer_uri": {
    what: "The customer URI Sectigo assigns to the account. The scan node sends it as the customerUri header on every request.",
    why: "Sectigo requires it with the user name and password. It names the account.",
    example: "cst1152.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2626
  "cbsrc.ca.sectigo_login": {
    what: "The Certificate Manager user name. The scan node sends it as the login header, with the password and customer URI.",
    why: "Give the user permission to list and download certificates. The collector does not call the keystore download.",
    example: "admin_customer1152.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2630
  "cbsrc.ca.sectigo_password": {
    what: "The password of that user. Encrypted at rest and sent only to the scan node, as the password header Sectigo requires.",
    why: "Changing the address, user, customer URI, CA or node clears it, so it is not sent to a different account.",
    example: "The password of the Certificate Manager user.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2448-2457 — read-only policy; encrypted at rest
  "cbsrc.ca.vault_token": {
    what: "A Vault token bound to the read-only policy shown below. Encrypted at rest and sent only to the scan node; changing the address, CA or node clears it.",
    why: "The policy lets it list PKI mounts and transit keys without signing or decrypting.",
    example: "A periodic token created with vault token create -policy=zs-cbom-read.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2458-2466 — the read-only HCL policy
  "cbsrc.ca.vault_policy": {
    what: "The Vault policy to bind to the token: read and list on PKI and transit metadata only.",
    why: "Review it before creating the token; it grants no sign, issue or decrypt rights.",
    example: "vault policy write zs-cbom-read zs-cbom-read.hcl.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2474 — PEM, encrypted at rest
  "cbsrc.ca.client_cert": {
    what: "The PEM client certificate the scan node presents to the EJBCA REST API. Encrypted at rest and sent only to the scan node.",
    why: "EJBCA admits only clients whose certificate maps to an administrator role.",
    example: "zs-cbom-reader.crt issued by the EJBCA ManagementCA.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2475-2484 — PEM, unencrypted; encrypted at rest
  "cbsrc.ca.client_key": {
    what: "The unencrypted PEM private key of the client certificate. Encrypted at rest and sent only to the scan node; changing the address, CA or node clears it.",
    why: "Give the matching EJBCA role read-only rights so the key cannot issue certificates.",
    example: "-----BEGIN PRIVATE KEY----- ....",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2491-2499 — optional PEM; verified before signing in
  "cbsrc.ca.ca_pem": {
    what: "Optional PEM certificate of the CA that issued the server's TLS (or WinRM) certificate. The node verifies the server with it before signing in.",
    why: "Needed when the server uses a private CA; without it the TLS check fails.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2618-2619 — up to 64 characters
  "cbsrc.idp.name": {
    what: "A name for this identity provider, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each signing key found records it as its source.",
    example: "Okta workforce.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2622-2630 — a GUID
  "cbsrc.idp.tenant": {
    what: "The GUID of your Microsoft Entra directory (tenant).",
    why: "The app registration signs in to this tenant only.",
    example: "72f988bf-86f1-41af-91ab-2d7cd011db47.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2641-2650,2636 — HTTPS, up to 512 characters
  "cbsrc.idp.base_url": {
    what: "Okta: your Okta domain. Keycloak: the base URL of the server. ADFS: the server address; its public OpenID metadata and federation metadata are read from it. HTTPS, up to 512 characters.",
    why: "Signing keys are read from this address's public metadata.",
    example: "https://adfs.bank.in for ADFS.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2653-2655 — up to 128 characters
  "cbsrc.idp.realm": {
    what: "The Keycloak realm whose clients and keys are read, up to 128 characters.",
    why: "Each realm has its own signing keys.",
    example: "corp.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2658-2660 — Entra application ID or Keycloak client ID
  "cbsrc.idp.client": {
    what: "Entra ID: the application (client) ID of the app registration with Application.Read.All. Keycloak: the confidential client with read-only access to clients and keys.",
    why: "With it ZeroShield also reads the app registrations' certificates and secrets metadata.",
    example: "zs-cbom-reader.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2663, frontend/components/cbom/sources/CloudIdentityTab.tsx:2663, frontend/components/cbom/sources/CloudIdentityTab.tsx:2662-2670 — optional; encrypted at rest
  "cbsrc.idp.secret": {
    what: "Optional, not asked for ADFS. The Okta API token or the client secret. Signing keys are read from public metadata without it; with it, more is read. Encrypted at rest and never shown again.",
    why: "Without it, only the provider's published signing keys are inventoried.",
    example: "A read-only Okta API token.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2710-2732 — HTTPS, up to 1,000 characters
  "cbsrc.idp.saml_url": {
    what: "The HTTPS address of an identity provider's SAML metadata, up to 1,000 characters. Its signing and encryption certificates are read from it.",
    why: "Covers identity providers without a dedicated connector (ADFS has its own row).",
    example: "https://idp.bank.in/saml/metadata.xml.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2710-2732 — HTTPS, up to 1,000 characters
  "cbsrc.idp.oidc_url": {
    what: "The HTTPS address of an OpenID Connect discovery document, up to 1,000 characters. Its JWKS signing keys are read from it.",
    why: "Covers any OIDC provider, including in-house ones.",
    example: "https://sso.bank.in/.well-known/openid-configuration.",
  },
} as const satisfies TipAreaText;

export default TEXT;
