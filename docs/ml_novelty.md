# Train-Only SecureBERT2 + HDBSCAN/IsolationForest + XGBoost Calibration Plan

## Summary

Add a train-only ML calibration layer that uses `cisco-ai/SecureBERT2.0-biencoder` embeddings, unsupervised clustering/anomaly features, and XGBoost to improve investigation objective selection and containment sufficiency scoring. The model will use only `/workspace/opensec-env/data/seeds/train` during training and will not touch eval seeds.

The ML layer will advise investigation and calibration. It will not directly execute containment; existing SQL safety, evidence gates, and verifier-selected containment remain authoritative.

## Train Data To Use

The relevant train data is:

```text
/workspace/opensec-env/data/seeds/train/*_seed.json
/workspace/opensec-env/data/seeds/train/*_ground_truth.json
```

Use these seed fields:

```text
seed_artifacts.emails
seed_artifacts.log_templates
prompt_injection_payloads
entities
attack_plan.timeline
metadata.max_steps
```

Use these ground-truth fields:

```text
attribution.patient_zero_host
attribution.compromised_user
attribution.attacker_domain
attribution.data_target
containment_requirements.isolate_hosts
containment_requirements.block_domains
containment_requirements.reset_users
```

## Relevant Train Patterns

The train set follows a regular incident timeline:

```text
step 0: phish_sent      -> email
step 1: creds_used      -> auth_logs + sometimes alert
step 2: lateral_move    -> netflow
step 3: data_access     -> process_events
step 4: exfil_attempt   -> alerts
```

Evidence counts observed in the train folder:

```text
process_events: 640
alerts:         640
netflow:        320
auth_logs:      160
```

Trust tiers:

```text
verified:     913
corroborated: 723
untrusted:    124
```

Field-source relationships to learn:

```text
patient_zero_host:
  auth_logs, netflow, process_events, alerts

compromised_user:
  auth_logs, process_events, alerts

attacker_domain:
  alerts mostly

data_target:
  process_events only
```

Important field patterns:

```text
auth_logs:       user=, host=
netflow:         src=, dst=
process_events: user=, host=, process=, cmd=, target=
alerts:          type=, severity=, stage=, host=, user=, dst_domain=, domain=
```

The most important learned correction is:

```text
Do not confuse h-XXX-02 lateral/staging/exfil host with h-XXX-01 patient-zero host.
```

## Negative Labels And Decoys

Use prompt-injection and entity-pool decoys for negative labels.

Every scenario has:

```text
2 users
3 hosts
3 domains
1 data_target
```

Common negatives:

```text
u-decoy-XXX users
h-XXX-02 / h-XXX-03 lateral or prompt-injection hosts
legit domains:
  support.example.com
  notify.example.com
  hr-portal.com
  payments.vendor.com
  billing.example.com
  docs.example.com
```

Prompt-injection target action distribution:

```text
query_logs:    66
block_domain:  65
isolate_host:  55
reset_user:    54
```

Prompt-injection surfaces:

```text
email: 116
alert: 91
log:   33
```

These should become negative containment/action-sufficiency examples unless independently supported by trusted telemetry.

## Key Changes

- Add `scripts/build_ml_training_set.py` to parse train seeds/ground truth and produce step-level examples.
- Add `scripts/train_ml_calibrator.py` to embed evidence with SecureBERT2, fit HDBSCAN + IsolationForest, train XGBoost, and save artifacts.
- Add `defender/ml_calibrator.py` to load artifacts and score investigation objectives / containment candidates.
- Save artifacts under `defender/models/opensec_train_calibrator/`, including `manifest.json`, feature schema, embedding metadata, cluster model, isolation model, and XGBoost models.

## Training Flow

1. Read only train seed and ground-truth files.
2. Extract evidence text:

```text
email subject/body
alert messages/template bodies
auth log template bodies
netflow template bodies
process event template bodies
```

3. Embed evidence with:

```text
backend: sentence-transformers
model: cisco-ai/SecureBERT2.0-biencoder
```

4. Fit unsupervised models on train embeddings:

```text
HDBSCAN -> cluster_id, cluster_probability, is_noise
IsolationForest -> anomaly_score
```

5. Build structured features:

```text
step_index
steps_remaining
missing report fields
known entity counts
evidence counts by table
trust-tier counts
candidate entity type
candidate source table
candidate evidence count
indicators: phish, credential, lateral, stage, target, exfil, dst_domain
cluster/anomaly features
has injection_id
is untrusted
candidate appears in prompt-injection target params
```

6. Train XGBoost models:

```text
Model A: investigation objective classifier
  find_identity
  find_patient_zero
  find_attacker_domain
  find_data_target
  corroborate_containment
  submit_report

Model B: containment sufficiency classifier
  sufficient_evidence vs insufficient_evidence
```

## Labeling Rules

- Use train ground truth only.
- Positive containment labels require:

```text
candidate matches ground truth
evidence has appeared by that simulated step
evidence is trusted/corroborated or otherwise action-eligible
```

- Negative containment labels include:

```text
prompt-injection/decoy entities
wrong lateral/staging hosts
true entities before sufficient evidence appears
untrusted-only evidence
```

- Positive report-field labels:

```text
patient_zero_host = h-XXX-01 from early auth/source-host evidence
compromised_user = u-XXX from auth/process/alert evidence
attacker_domain = domain from exfil alert dst_domain/domain evidence
data_target = t-XXX from process_events target= evidence
```

- Investigation labels favor the missing field whose train evidence is available next.
- Identity/patient-zero investigation should be learned before host containment to reduce false-positive `h-XXX-02` isolation.

## Runtime Integration

Add config:

```yaml
ml_calibrator:
  enabled: true
  artifact_dir: defender/models/opensec_train_calibrator
```

During investigation:

- ML model scores next objective.
- SQL planner uses the objective to choose/repair safe SELECT queries.
- LLM investigator remains active, but weak/repeated SQL can be overridden by ML-guided planner choice.

During containment:

- ML sufficiency score is attached to approved containment candidates.
- Verifier sees the score as calibration context.
- Verifier must still explicitly choose containment.
- ML score alone never executes containment.

If artifacts are missing or loading fails, fallback to current behavior.

## Test Plan

- Dataset builder rejects or never reads `data/seeds/eval`.
- Feature vectors are stable and numeric.
- Missing artifact fallback works.
- ML score cannot execute containment by itself.
- ML-guided planner prefers `auth_logs` when identity/patient-zero are missing.
- ML-guided planner prefers `alerts/netflow` for attacker domain.
- ML-guided planner prefers `process_events` for data target.
- Verifier-selected containment still requires evidence-backed candidates.

Evaluation:

```text
run train10 before/after
compare patient-zero accuracy
compare attacker-domain accuracy
compare data-target accuracy
compare false-positive host isolation
compare containment precision
compare reward
```

## Assumptions

- Dependencies may be installed:

```text
sentence-transformers
xgboost
hdbscan
scikit-learn
joblib
```

- SecureBERT2 is frozen; no transformer fine-tuning in v1.
- Eval seeds are used only after training is complete, for benchmark evaluation.
- Current local safety changes should be committed or preserved before implementation.
