function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function computeRisk(score) {
  if (score >= 70) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

function uniq(arr) {
  return [...new Set((arr || []).filter(Boolean))];
}

function normalizeDomains(list) {
  return uniq(
    (list || [])
      .map((s) => String(s || "").trim())
      .filter(Boolean)
      .map((s) => s.replace(/^https?:\/\//i, "").replace(/\/.*$/, ""))
      .map((s) => s.toLowerCase())
  );
}

function scanText(text) {
  const t = String(text || "");

  const findings = [];
  let score = 0;

  const rules = [
    {
      id: "remote_pipe_to_shell",
      severity: "HIGH",
      points: 55,
      test: (s) => /\b(curl|wget)\b[\s\S]{0,120}\|\s*(bash|sh|zsh|pwsh|powershell)\b/i.test(s),
      title: "Pipes remote content to a shell",
      detail: "Patterns like `curl ... | bash` are a common malware delivery mechanism. Prefer download + verify + run."
    },
    {
      id: "sudo_or_admin",
      severity: "MEDIUM",
      points: 18,
      test: (s) => /\bsudo\b|runas\b|start-process\b.*-verb\s+runas/i.test(s),
      title: "Uses elevated privileges",
      detail: "Admin rights increase blast radius. Prefer least-privilege sandbox and explicit approval gates."
    },
    {
      id: "destructive_rm",
      severity: "HIGH",
      points: 45,
      test: (s) => /\brm\s+-rf\b|\bdel\s+\/f\b|\bformat\b|\bmkfs\./i.test(s),
      title: "Potentially destructive delete/format commands",
      detail: "Detected destructive patterns. Block these in agent execution policies."
    },
    {
      id: "credential_hunting",
      severity: "HIGH",
      points: 40,
      test: (s) =>
        /\b(openai_api_key|api[_-]?key|secret|token|password)\b/i.test(s) ||
        /~\/\.ssh|id_rsa|authorized_keys|\.aws\/credentials|\.env\b/i.test(s),
      title: "Possible credential or secret access",
      detail: "Access to `.env`, SSH keys, cloud credentials, or secrets suggests credential-hunting. Require explicit consent + redaction."
    },
    {
      id: "env_dump",
      severity: "MEDIUM",
      points: 18,
      test: (s) => /\bprintenv\b|\benv\b(?!ironment)|process\.env|os\.environ/i.test(s),
      title: "Reads environment variables",
      detail: "Dumping environment variables can expose secrets. Restrict or redact sensitive keys."
    },
    {
      id: "network_exfil",
      severity: "MEDIUM",
      points: 16,
      test: (s) => /\b(nc|netcat|socat)\b|\bscp\b|\bcurl\b|\bwget\b|\binvoke-webrequest\b/i.test(s),
      title: "Network-capable commands present",
      detail: "Network tooling can be used for exfiltration or downloading payloads. Prefer domain allowlists."
    },
    {
      id: "code_download_execute",
      severity: "HIGH",
      points: 30,
      test: (s) => /\bpython\b[\s\S]{0,40}-c\b|\bnode\b[\s\S]{0,40}-e\b|\bpowershell\b[\s\S]{0,40}-enc\b/i.test(s),
      title: "Inline code execution flags detected",
      detail: "Inline execution can hide behavior. Consider blocking or requiring approval."
    },
    {
      id: "persistence",
      severity: "MEDIUM",
      points: 16,
      test: (s) => /\b(crontab|launchctl|systemctl\s+enable|schtasks|registry|reg\s+add)\b/i.test(s),
      title: "Possible persistence mechanisms",
      detail: "Persistence should be tightly controlled in any agent runner."
    }
  ];

  for (const r of rules) {
    if (r.test(t)) {
      findings.push({ title: r.title, severity: r.severity, detail: r.detail, ruleId: r.id, points: r.points });
      score += r.points;
    }
  }

  score = clamp(score, 0, 100);
  const risk = computeRisk(score);

  // Suggested blocklist patterns based on findings
  const suggestedBlocked = [];
  if (findings.some((f) => f.ruleId === "remote_pipe_to_shell")) {
    suggestedBlocked.push("curl | bash", "wget | bash", "Invoke-WebRequest | powershell");
  }
  if (findings.some((f) => f.ruleId === "destructive_rm")) {
    suggestedBlocked.push("rm -rf", "mkfs.*", "format");
  }
  if (findings.some((f) => f.ruleId === "credential_hunting")) {
    suggestedBlocked.push("cat ~/.ssh/id_rsa", "cat .env", "read ~/.aws/credentials");
  }

  // Extract domains from URLs found in the input
  const urlMatches = t.match(/\bhttps?:\/\/[^\s'")]+/gi) || [];
  const extractedDomains = [];
  for (const u of urlMatches.slice(0, 20)) {
    try {
      extractedDomains.push(new URL(u).hostname);
    } catch {}
  }

  const summary =
    risk === "HIGH"
      ? "High-risk patterns detected. Treat as unsafe by default."
      : risk === "MEDIUM"
      ? "Some risky capabilities detected. Add guardrails and approvals."
      : "No major red flags detected by heuristics. Still review before running.";

  return {
    ok: true,
    risk,
    score,
    summary,
    findings: findings
      .sort((a, b) => b.points - a.points)
      .map(({ title, severity, detail }) => ({ title, severity, detail })),
    suggested: {
      blocklist: { command_patterns: uniq(suggestedBlocked) },
      allowlist: { domains: normalizeDomains(extractedDomains) }
    }
  };
}

function buildPolicy({ suggested, editor }) {
  // editor defaults
  const network = editor?.network === "allowed" ? "allowed" : "restricted";
  const filesystem = editor?.filesystem === "read_write" ? "read_write" : "read_only";
  const approvalsEnabled = editor?.approvalsEnabled !== false; // default true
  const extraDomains = normalizeDomains(editor?.allowlistDomains || []);

  const require_user_approval_for = approvalsEnabled
    ? ["write_files", "execute_commands", "network_requests"]
    : [];

  return {
    version: "0.2",
    mode: "guardrails",
    default: {
      network,
      filesystem,
      require_user_approval_for
    },
    blocklist: {
      command_patterns: uniq([...(suggested?.blocklist?.command_patterns || [])])
    },
    allowlist: {
      domains: uniq([...(suggested?.allowlist?.domains || []), ...extraDomains])
    },
    notes: [
      "This is a suggested policy for an agent runner. Enforce with a sandbox + explicit approvals.",
      "Prefer domain allowlists; keep network restricted unless you truly need it."
    ]
  };
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", ["POST"]);
    return res.status(405).json({ error: "Method not allowed. Use POST." });
  }

  try {
    const { text, editor } = req.body || {};
    if (typeof text !== "string" || text.trim().length === 0) {
      return res.status(400).json({ error: "Missing 'text' (string)." });
    }
    if (text.length > 200_000) {
      return res.status(413).json({ error: "Input too large. Keep it under 200k characters." });
    }

    const scan = scanText(text);
    const policy = buildPolicy({ suggested: scan.suggested, editor });

    return res.status(200).json({
      ...scan,
      policy
    });
  } catch (err) {
    return res.status(500).json({ error: "Internal error.", detail: String(err?.message || err) });
  }
}
