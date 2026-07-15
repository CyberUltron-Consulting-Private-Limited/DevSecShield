// clinithread-aibom — sample Cedar runtime-governance policies (ADVISORY).
// Generated from an AI-BOM inventory. Load alongside the exported entities
// and authorize (principal, action, resource) at your gateway/application.
// These are STARTING-POINT policies; a reviewer must adapt them before use.

// 1) Deny use of any UNSANCTIONED (shadow-AI) component.
forbid (principal, action, resource)
when { resource has sanctioned && resource.sanctioned == false };

// 2) Deny routing inference to a serving vendor without a signed BAA.
forbid (principal, action == Action::"serve", resource)
when { resource has baa && resource.baa == false };

// 3) Deny use of a deployment site flagged drift-detected until
//    it has been re-validated.
forbid (principal, action, resource)
when { resource has drift_status &&
       resource.drift_status == "drift-detected" };

// 4) Permit use of sanctioned components (closes the default-deny model).
permit (principal, action, resource)
when { resource has sanctioned && resource.sanctioned == true };
