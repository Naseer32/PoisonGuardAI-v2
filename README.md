# PoisonGuardAI

**An on-chain registry for training-data integrity, with AI-validated backdoor-risk assessments, built on GenLayer.**

Live demo: https://poisonguardai-web.vercel.app/
Contract (GenLayer Bradbury testnet): `0x0932c34aa6e664245f7C3A7D4944B24217d9F061`

## The problem

Anyone who trains or fine-tunes a model on third-party data has to trust that the data was not tampered with. Poisoned datasets can plant backdoors: the model behaves normally until a trigger appears. Today, claims like "this dataset was audited" live in blog posts and PDFs. Nobody can check what was claimed, when, or whether the claim was tested.

## What PoisonGuardAI does

1. **Register** a dataset: name, version, SHA-256 content hash, provenance and the model it trains.
2. **Submit evidence** (up to 8 items): provenance records, label audits, feature analyses, trigger tests, control tests, clean baselines and independent reproductions. Each item is marked as an OBSERVATION or an ALLEGATION. Behavioral tests carry trial and hit counts.
3. **Assess**: the contract computes deterministic metrics (trigger rate vs control/baseline rate, differential, qualifying runs). When the evidence is rich enough, GenLayer validators also run an LLM evaluation and must reach consensus.
4. **Read the result**: outcome (`LOW_RISK`, `ELEVATED_RISK`, `HIGH_RISK`, `INCONCLUSIVE`), score 0-100, evidence quality, findings, alternative explanations, missing tests, confidence limitations and the next verification step.

Contract rules constrain the LLM: score bands per outcome, evidence-quality caps, and an `INCONCLUSIVE` result when the evidence is too thin. A result is marked **stale** if evidence changed after the last assessment. Status changes follow a fixed transition graph (REGISTERED, EVIDENCE_SUBMITTED, ASSESSED, UNDER_REVIEW, REJECTED, CLOSED).

## Contract methods

| Method | Type |
|---|---|
| `register_dataset` | write |
| `submit_evidence` | write |
| `assess_dataset` | write |
| `update_assessment_status` | write |
| `get_assessment` | view |
| `get_risk_summary` | view |
| `get_dataset_count` | view |

## How to use the web app

1. Open the demo on any device. Reading works without a wallet.
2. **Lookup**: enter an assessment id and press *Risk summary* or *Full assessment*.
3. To write, open the page in a wallet browser, press **Connect**, then use the Register, Evidence, Assess and Status tabs.
4. The app shows the transaction hash, waits for `ACCEPTED`, and reads the result back from the chain. LLM assessments can take several minutes; if the wait times out, check Lookup again, because the transaction keeps running on the network.

## Honest limitations

- Evidence is **submitter-supplied and unverified**. The contract does not run or scan any model. It records claims, scores how well they are supported, and says what is missing.
- The score is a structured judgement of the evidence, not a safety certificate. A matching hash proves identity of the content, not safety.
- The sample assessments in the live deployment use synthetic test data.

## Repository structure

```text
contracts/poison_guard_ai.py   Intelligent contract (Python)
tests/                         Direct Mode and Studio test suites
web/                           Single-file frontend (genlayer-js), deployed on Vercel
README_TESTING.md              How to run the tests

Tests
The Direct Mode suite (tests/direct, 36 tests) passes on the compact contract. See README_TESTING.md for how to run it.
Run the frontend locally

cd web
python -m http.server 8000

Open http://localhost:8000. Wallet connection needs an https origin or a wallet browser that allows localhost.
Built with
GenLayer intelligent contracts (Python), genlayer-js, plain HTML, CSS and JavaScript.
