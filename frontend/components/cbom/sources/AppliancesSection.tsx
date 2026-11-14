"use client";

// Network appliances (CBOM Sources > Network): read-only configuration pulls from Cisco IOS / ASA, FortiOS (SSH show
// commands) and PAN-OS / F5 BIG-IP (API GETs) through a scan node.  Kind "appliance" in
// backend/utilities/cbom_sources/kinds.py (ApplianceConfig); collector scan_node/zs_scan_node/collectors/appliance.py.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CirclePlay, Loader2, Plus, Trash2 } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  createCbomSource,
  deleteCbomSource,
  listCbomSources,
  testCbomSource,
  type CbomScanNode,
  type CbomSource,
} from "@/utils/backend_api";

import { cbomSourcesKeys } from "./keys";
import { ConfirmDialog, EmptyState, Field, NodeSelect, SecretField, SectionCard, TestStatusBadge, Truncate } from "./shared";
import { InfoTip } from "@/components/ui/info-tip";

type Vendor = "cisco_ios" | "cisco_asa" | "fortios" | "panos" | "f5_bigip";
const VENDORS: { value: Vendor; label: string; transport: "ssh" | "api"; reads: string }[] = [
  { value: "cisco_ios", label: "Cisco IOS / IOS XE", transport: "ssh", reads: "show running-config (ip ssh, ip http, crypto sections), show crypto key mypubkey rsa" },
  { value: "cisco_asa", label: "Cisco ASA", transport: "ssh", reads: "show running-config ssl / ssh / crypto ikev1 / crypto ikev2, show crypto key mypubkey rsa (account must land in privileged EXEC)" },
  { value: "fortios", label: "FortiOS (FortiGate)", transport: "ssh", reads: "show full-configuration system global, vpn ipsec phase1-interface, phase2-interface" },
  { value: "panos", label: "PAN-OS (XML API)", transport: "api", reads: "type=config&action=show (running config): IKE/IPsec crypto profiles, IKE gateways, SSL/TLS service profiles" },
  { value: "f5_bigip", label: "F5 BIG-IP (iControl REST)", transport: "api", reads: "GET /mgmt/tm/ltm/profile/client-ssl and /mgmt/tm/sys/crypto/key (key type and size only)" },
];
const VENDOR: Record<string, (typeof VENDORS)[number]> = Object.fromEntries(VENDORS.map((v) => [v.value, v]));
const HOST_RE = /^[A-Za-z0-9._:-]{1,253}$/;

function lines(text: string): string[] {
  return text.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
}

export default function AppliancesSection({ teamId, nodes, onNavigate }: { teamId: number; nodes: CbomScanNode[]; onNavigate: (tab: string) => void }) {
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<CbomSource | null>(null);
  const query = useQuery({
    queryKey: cbomSourcesKeys.sources(teamId, "network"),
    queryFn: () => listCbomSources(teamId, "network"),
    retry: 1,
    refetchInterval: (q) => (q.state.data?.sources.some((s) => s.last_test_status === "pending") ? 6000 : 30000),
  });
  const appliances = (query.data?.sources ?? []).filter((s) => s.kind === "appliance");
  const invalidate = () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
  const test = useMutation({ mutationFn: (id: number) => testCbomSource(teamId, id), onSettled: invalidate });
  const remove = useMutation({ mutationFn: (id: number) => deleteCbomSource(teamId, id), onSettled: invalidate, onSuccess: () => setDeleting(null) });

  return (
    <SectionCard
      infoId="cbsrc.app.card"
      title="Network appliances"
      description="Read-only configuration of routers, firewalls and load balancers: TLS, SSH and IKE/IPsec settings and key sizes. Only show commands or API reads are sent."
      actions={
        !adding && (
          <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => setAdding(true)} data-testid="appliance-add">
            <Plus className="h-4 w-4 mr-2" />
            Add appliance
          </Button>
        )
      }
    >
      <div className="space-y-4">
        {adding && <ApplianceForm teamId={teamId} nodes={nodes} onDone={() => setAdding(false)} onSaved={invalidate} onNavigate={onNavigate} />}
        {appliances.length === 0 && !adding ? (
          <EmptyState title="No appliances yet" body="Add a Cisco, FortiGate, Palo Alto or F5 device to read its crypto configuration." />
        ) : (
          appliances.length > 0 && (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Vendor <InfoTip id="cbsrc.app.col.vendor" /></TableHead>
                    <TableHead>Targets <InfoTip id="cbsrc.app.col.targets" /></TableHead>
                    <TableHead>Node <InfoTip id="cbsrc.col.node" /></TableHead>
                    <TableHead>Test <InfoTip id="cbsrc.col.test" /></TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {appliances.map((s) => (
                    <TableRow key={s.id} data-testid={`appliance-row-${s.id}`}>
                      <TableCell className="font-medium">{s.name}</TableCell>
                      <TableCell>{VENDOR[s.config?.vendor]?.label ?? s.config?.vendor}</TableCell>
                      <TableCell className="font-mono text-xs max-w-[240px]">
                        <Truncate text={(s.config?.targets ?? []).join(", ")} />
                      </TableCell>
                      <TableCell>{s.node_name ?? "—"}</TableCell>
                      <TableCell>
                        <TestStatusBadge status={s.last_test_status} title={s.last_test_summary} />
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        <Button variant="ghost" size="sm" className="cursor-pointer" title="Test the connection from the scan node"
                          disabled={test.isPending} onClick={() => test.mutate(s.id)}>
                          <CirclePlay className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" className="cursor-pointer text-red-600" title="Delete" onClick={() => setDeleting(s)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )
        )}
      </div>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete appliance?"
        description={`${deleting?.name ?? ""} and its stored credential are removed. Collected results stay in past runs.`}
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
      />
    </SectionCard>
  );
}

function ApplianceForm({
  teamId,
  nodes,
  onDone,
  onSaved,
  onNavigate,
}: {
  teamId: number;
  nodes: CbomScanNode[];
  onDone: () => void;
  onSaved: () => void;
  onNavigate: (tab: string) => void;
}) {
  const [vendor, setVendor] = useState<Vendor>("cisco_ios");
  const [name, setName] = useState("");
  const [targets, setTargets] = useState("");
  const [port, setPort] = useState("");
  const [login, setLogin] = useState("zs-cbom");
  const [secret, setSecret] = useState("");
  const [knownHosts, setKnownHosts] = useState("");
  const [caPem, setCaPem] = useState("");
  const [nodeId, setNodeId] = useState<number | null>(nodes.length === 1 ? nodes[0].id : null);
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  const ssh = VENDOR[vendor].transport === "ssh";

  const save = useMutation({
    mutationFn: ({ test }: { test: boolean }) =>
      createCbomSource(teamId, {
        kind: "appliance",
        name: name.trim(),
        node_id: nodeId ?? undefined,
        config: {
          vendor,
          targets: lines(targets),
          port: port ? Number(port) : null,
          login_user: login.trim() || "zs-cbom",
          credential_type: "password",
          host_key_policy: "pinned",
          known_hosts: ssh ? knownHosts : null,
          ca_pem: ssh ? null : caPem.trim() || null,
        },
        secrets: { [vendor === "panos" ? "api_key" : "password"]: secret },
        test_after_save: test,
      }),
    onSuccess: onDone,
    onSettled: onSaved,
  });

  const submit = (test: boolean) => {
    const hosts = lines(targets);
    const portNumber = Number(port);
    const next: Record<string, string | null> = {
      name: /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(name.trim()) ? null : "Use letters, digits, spaces, . _ - (64 at most)",
      targets: hosts.length === 0 ? "Enter at least one address" : hosts.find((h) => !HOST_RE.test(h)) ? "One address or host name per line" : null,
      port: port && !(Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535) ? "1 to 65535" : null,
      secret: secret ? null : vendor === "panos" ? "Paste the API key of a read-only admin" : "Enter the read-only account's password",
      knownHosts: ssh && !knownHosts.trim() ? "Paste the device's known_hosts line (ssh-keyscan), so the password only goes to the real device" : null,
      node: nodeId ? null : "Choose the scan node that reaches the appliance",
    };
    setErrors(next);
    if (Object.values(next).some(Boolean)) return;
    save.mutate({ test });
  };

  return (
    <div className="space-y-4 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="appliance-form">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Field infoId="cbsrc.app.vendor" label="Vendor" htmlFor="appliance-vendor" required hint={`Reads: ${VENDOR[vendor].reads}`}>
          <Select value={vendor} onValueChange={(v) => setVendor(v as Vendor)}>
            <SelectTrigger id="appliance-vendor" className="w-full cursor-pointer" data-testid="appliance-vendor">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {VENDORS.map((v) => (
                <SelectItem key={v.value} value={v.value} className="cursor-pointer">
                  {v.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field infoId="cbsrc.app.name" label="Name" htmlFor="appliance-name" required error={errors.name}>
          <Input id="appliance-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} placeholder="Edge firewalls" data-testid="appliance-name" />
        </Field>
        <Field infoId="cbsrc.app.devices" label="Devices" htmlFor="appliance-targets" required error={errors.targets} hint="One address or host name per line; all use the same account">
          <Textarea id="appliance-targets" className="font-mono text-sm min-h-[72px]" value={targets} spellCheck={false}
            onChange={(e) => setTargets(e.target.value)} placeholder={"10.0.0.1\nfw-2.corp.example"} data-testid="appliance-targets" />
        </Field>
        <div className="grid grid-cols-2 gap-4">
          <Field infoId="cbsrc.app.port" label="Port" htmlFor="appliance-port" error={errors.port} hint={ssh ? "Default 22" : "Default 443"}>
            <Input id="appliance-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, "").slice(0, 5))} data-testid="appliance-port" />
          </Field>
          {vendor !== "panos" && (
            <Field infoId="cbsrc.app.login" label="Login" htmlFor="appliance-login" hint="A read-only account">
              <Input id="appliance-login" value={login} maxLength={64} onChange={(e) => setLogin(e.target.value)} data-testid="appliance-login" />
            </Field>
          )}
        </div>
        <SecretField infoId="cbsrc.app.secret" id="appliance-secret" label={vendor === "panos" ? "API key" : "Password"} value={secret} onChange={setSecret} required error={errors.secret} />
        <Field infoId="cbsrc.app.node" label="Scan node" htmlFor="appliance-node" required error={errors.node}>
          <NodeSelect id="appliance-node" nodes={nodes} value={nodeId} onChange={setNodeId} />
        </Field>
        {ssh ? (
          <Field infoId="cbsrc.app.known_hosts" label="Pinned host key (known_hosts)" htmlFor="appliance-known-hosts" required error={errors.knownHosts}
            hint="ssh-keyscan -p <port> <device> from a trusted machine; a different key stops the login before the password is sent">
            <Textarea id="appliance-known-hosts" className="font-mono text-xs min-h-[72px]" value={knownHosts} spellCheck={false}
              onChange={(e) => setKnownHosts(e.target.value)} data-testid="appliance-known-hosts" />
          </Field>
        ) : (
          <Field infoId="cbsrc.app.ca" label="CA certificate (PEM)" htmlFor="appliance-ca" hint="If the management certificate is not publicly trusted; the certificate is always verified">
            <Textarea id="appliance-ca" className="font-mono text-xs min-h-[72px]" value={caPem} spellCheck={false}
              onChange={(e) => setCaPem(e.target.value)} data-testid="appliance-ca" />
          </Field>
        )}
      </div>
      {nodes.length === 0 && (
        <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => onNavigate("scan-nodes")}>
          Add a scan node first
        </Button>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="outline" className="cursor-pointer" onClick={onDone} disabled={save.isPending}>
          Cancel
        </Button>
        <Button variant="outline" className="cursor-pointer" disabled={save.isPending} onClick={() => submit(false)} data-testid="appliance-save">
          {save.isPending && save.variables?.test === false && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Save
        </Button>
        <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending} onClick={() => submit(true)} data-testid="appliance-save-test">
          {save.isPending && save.variables?.test === true && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Save and test
        </Button>
      </div>
    </div>
  );
}
