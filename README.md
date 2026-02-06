# ClawShield (MVP)

ClawShield is a simple "Agent / Skill Security Checker".
Paste a prompt, script, or skill snippet and get:
- Risk level: LOW / MEDIUM / HIGH
- Findings with explanations
- A suggested guardrail policy JSON

## Tech
- Next.js (Pages Router)
- `/api/scan` serverless endpoint (heuristic scanner)
- Designed to deploy easily on Vercel

## Run locally
```bash
npm install
npm run dev
