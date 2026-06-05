# NetMind AI — Validation Aggregate Report

Generated: 2026-06-05T11:56:42.538491+00:00

## Per-Rule Metrics

| Rule | Labeled PCAPs | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy |
|------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| NET-001 (Port Scan Detection) | 2 | 1 | 1 | 0 | 0 | 0.500 | 1.000 | 0.667 | 1.000 | 0.500 |
| NET-002 (DNS Tunneling Detection) | 2 | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| NET-003 (FTP Brute Force Detection) | 2 | 0 | 0 | 2 | 0 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| NET-004 (SMTP Abuse Detection) | 2 | 0 | 0 | 2 | 0 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |

## Overall

- **Labeled PCAPs**: 2
- **Macro avg precision**: 0.3750
- **Macro avg recall**: 0.5000
- **Macro avg F1**: 0.4167
- **Total TP**: 2
- **Total FP**: 1
- **Total TN**: 5
- **Total FN**: 0

---

_Method: per-rule confusion matrix across all PCAPs with ground-truth labels. PCAPs without labels are excluded._
