function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
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

function computeRisk(score, thresholds) {
  const { medium = 35, high = 70 } = thresholds || {};
  if (score >= high) return "HIGH";
  if (score >= medium) return "MEDIUM";
  return "LOW";
}

function getPackConfig(pack) {
  const p = (pack || "basic").toLowerCase();
  if (p === "strict") {
    return {
      name: "STRICT",
      thresholds: { medium: 28, high: 55 },
      multiplier: 1.15,
      enabled: "all"
    };
  }
  if (p === "paranoid") {
    return {
      name: "PARANOID",
      thresholds: { medium: 22, high: 45 },
      multiplier: 1.3,
      enabled: "all_plus"
    };
  }
  return {
    name: "BASIC",
    thresholds: { medium: 35, high: 70 },
    multiplier: 1.0,
    enabled: "core"
  };
}

function findMatchesByLine(text, regexes, maxMatches = 8) {
  const lines = String(text || "").split(/\r?\n/);
  const matches = [];
  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i];
    for (const rx of regexes) {
      try {
        if (rx.test(lineText)) {
          matches.push({ line: i + 1, text: lineText.slice(0, 240) });
          break;
        }
      } catch {}
    }
    if (matches.length >= maxMatches) break;
  }
  return matches;
}

function extractDomainsFromText(text) {
  const t = String(text || "");
  const urlMatches = t.match(/\bhttps?:\/\/[^\s'")]+/gi) || [];
  const extracted = [];
  for (const u of urlMatches.slice(0, 20)) {
    try {
      extracted.push(new URL(u).hostname);
    } catch {}
  }
  return normalizeDomains(extracted);
}

function scanText(text, packName) {
  const t = String(text || "");
  const pack = getPackConfig(packName);

  const CORE_RULES = [
    {
      id: "remote_pipe_to_shell",
      severity: "HIGH",
      basePoints: 55,
      regexes: [
        /\b(curl|wget)\b[\s\S]{0,120}\|\s*(bash|sh|zsh|pwsh|powershell)\b/i
      ],
      title: "Pipes remote content to a shell",
      simple: "Det här är en klassisk “ladda ner och kör direkt”-risk (kan installera malware).",
      dev: "Detected pattern like `curl/wget ... | bash/sh/powershell`. Prefer download + checksum/signature verification + manual execution."
    },
    {
      id: "sudo_or_admin",
      severity: "MEDIUM",
      basePoints: 18,
      regexes: [/\bsudo\b/i, /-verb\s+runas/i, /\brunas\b/i],
      title: "Uses elevated privileges",
      simple: "Försöker köra med admin-rättigheter → större skada om något är fel.",
      dev: "Elevation request detected (sudo/RunAs). Enforce least privilege + explicit approval gates."
    },
    {
      id: "destructive_rm",
      severity: "HIGH",
      basePoints: 45,
      regexes: [/\brm\s+-rf\b/i, /\bmkfs\./i, /\bformat\b/i, /\bdel\s+\/f\b/i],
      title: "Potentially destructive delete/format commands",
      simple: "Kan radera eller förstöra data. Blockera detta i en agent.",
      dev: "Destructive patterns detected (rm -rf / mkfs / format / del /f). Should be denied by default."
    },
    {
      id: "credential_hunting",
      severity: "HIGH",
      basePoints: 40,
      regexes: [
        /\b(openai_api_key|api[_-]?key|secret|token|password)\b/i,
        /~\/\.ssh/i,
        /id_rsa/i,
        /\.aws\/credentials/i,
        /\b\.env\b/i
      ],
      title: "Possible credential or secret access",
      simple: "Försöker läsa nycklar/hemligheter (t.ex. .env eller ssh-nycklar).",
      dev: "Potential secrets access detected (.env, ~/.ssh, cloud creds, secret keywords). Require explicit consent + redaction."
    },
    {
      id: "env_dump",
      severity: "MEDIUM",
      basePoints: 18,
      regexes: [/\bprintenv\b/i, /\bprocess\.env\b/i, /\bos\.environ\b/i, /\benv\b(?!ironment)/i],
      title: "Reads environment variables",
      simple: "Kan råka läcka hemligheter från miljövariabler.",
      dev: "Environment variable access detected (printenv/process.env/os.environ). Redact sensitive keys."
    },
    {
      id: "network_exfil",
      severity: "MEDIUM",
      basePoints: 16,
      regexes: [/\b(nc|netcat|socat)\b/i, /\bscp\b/i, /\bcurl\b/i, /\bwget\b/i, /\binvoke-webrequest\b/i],
      title: "Network-capable commands present",
      simple: "Nätverk kan användas för att skicka ut data eller hämta payloads.",
      dev: "Network tooling detected. Restrict egress and use domain allowlists."
    },
    {
      id: "inline_exec_flags",
      severity: "HIGH",
      basePoints: 30,
      regexes: [/\bpython\b.*\s-c\b/i, /\bnode\b.*\s-e\b/i, /\bpowershell\b.*\s-enc\b/i],
      title: "Inline / encoded execution flags detected",
      simple: "Kör kod “inline”/kodat → svårt att se vad som händer.",
      dev: "Inline execution flags detected (python -c, node -e, powershell -enc). Often used to hide behavior."
    },
    {
      id: "persistence",
      severity: "MEDIUM",
      basePoints: 16,
      regexes: [/\bcrontab\b/i, /\blaunchctl\b/i, /\bsystemctl\s+enable\b/i, /\bschtasks\b/i, /\breg\s+add\b/i],
      title: "Possible persistence mechanisms",
      simple: "Försöker göra sig “permanent” (cron/service/scheduled task).",
      dev: "Persistence indicators detected (cron/services/scheduled tasks/registry). Should require approval."
    }
  ];

  const EXTRA_RULES = [
    {
      id: "base64_obfuscation",
      severity: "MEDIUM",
      basePoints: 22,
      regexes: [/\bbase64\b/i, /frombase64string/i, /\batob\(/i],
      title: "Possible obfuscation / base64 decoding",
      simple: "Ser ut som att text/kod avkodas (kan dölja en payload).",
      dev: "Base64/obfuscation indicators detected (base64/FromBase64String/atob). Consider decoding in a safe viewer and scanning output."
    },
    {
      id: "eval_like",
      severity: "HIGH",
      basePoints: 28,
      regexes: [/\beval\(/i, /\bexec\(/i, /\bFunction\(/i],
      title: "Dynamic execution (eval/exec)",
      simple: "Kör dynamisk kod (svårt att kontrollera).",
      dev: "Dynamic execution detected (eval/exec/Function). High-risk in agent contexts; block or require approval."
    },
    {
      id: "npm_postinstall",
      severity: "MEDIUM",
      basePoints: 20,
      regexes: [/\bpostinstall\b/i, /\bnpm\s+install\b/i, /\byarn\s+add\b/i, /\bpnpm\s+add\b/i],
      title: "Dependency install can execute scripts",
      simple: "Paketinstallation kan köra scripts (postinstall).",
      dev: "Dependency install detected. npm/yarn/pnpm may run lifecycle scripts; pin versions and disable scripts if possible."
    }
  ];

  const rulesToUse =
    pack.enabled === "core"
      ? CORE_RULES
      : pack.enabled === "all"
        ? CORE_RULES
        : [...CORE_RULES, ...EXTRA_RULES]; // all_plus

  const findings = [];
  let score = 0;

  for (const r of rulesToUse) {
    // Whole-text match for trigger
    const triggered = r.regexes.some((rx) => {
      try { return rx.test(t); } catch { return false; }
    });
    if (!triggered) continue;

    const points = Math.round(r.basePoints * pack.multiplier);
    score += points;

    const matches = findMatchesByLine(t, r.regexes, 8);

    findings.push({
      ruleId: r.id,
      title: r.title,
      severity: r.severity,
      points,
      explainSimple: r.simple,
      explainDev: r.dev,
      matches
    });
  }

  score = clamp(score, 0, 100);
  const risk = computeRisk(score, pack.thresholds);

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
  if (findings.some((f) => f.ruleId === "eval_like")) {
    suggestedBlocked.push("eval(", "exec(", "Function(");
  }

  const extractedDomains = extractDomainsFromText(t);

  const summary =
    risk === "HIGH"
      ? "High-risk patterns detected. Treat as unsafe by default."
      : risk === "MEDIUM"
        ? "Some risky capabilities detected. Add guardrails and approvals."
        : "No major red flags detected by heuristics. Still review before running.";

  return {
    ok: true,
    pack: pack.name,
    thresholds: pack.thresholds,
    risk,
    score,
    summary,
    findings: findings.sort((a, b) => b.points - a.points),
    suggested: {
      blocklist: { command_patterns: uniq(suggestedBlocked) },
      allowlist: { domains: extractedDomains }
    }
  };
}

function buildPolicy({ suggested, editor, packName }) {
  const pack = getPackConfig(packName);

  const network = editor?.network === "allowed" ? "allowed" : "restricted";
  const filesystem = editor?.filesystem === "read_write" ? "read_write" : "read_only";
  const approvalsEnabled = editor?.approvalsEnabled !== false;
  const extraDomains = normalizeDomains(editor?.allowlistDomains || []);

  const require_user_approval_for = approvalsEnabled
    ? ["write_files", "execute_commands", "network_requests"]
    : [];

  return {
    version: "0.3",
    mode: "guardrails",
    rule_pack: pack.name,
    thresholds: pack.thresholds,
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
      "Keep network restricted unless needed; prefer domain allowlists and TLS-only."
    ]
  };
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", ["POST"]);
    return res.status(405).json({ error: "Method not allowed. Use POST." });
  }

  try {
    const { text, editor, pack } = req.body || {};
    if (typeof text !== "string" || text.trim().length === 0) {
      return res.status(400).json({ error: "Missing 'text' (string)." });
    }
    if (text.length > 200_000) {
      return res.status(413).json({ error: "Input too large. Keep it under 200k characters." });
    }

    const scan = scanText(text, pack);
    const policy = buildPolicy({ suggested: scan.suggested, editor, packName: pack });

    return res.status(200).json({
      ...scan,
      policy
    });
  } catch (err) {
    return res.status(500).json({ error: "Internal error.", detail: String(err?.message || err) });
  }
}
