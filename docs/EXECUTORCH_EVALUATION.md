# ExecuTorch Integration Evaluation

## Executive Summary

ExecuTorch integration has been **evaluated and deferred** for this project. The existing SMS Specialist Classifier is a lightweight logistic regression model with TF-IDF features, already implemented in pure Kotlin. ExecuTorch is designed for PyTorch model execution (transformers, CNNs, etc.) and would introduce significant dependency overhead without measurable benefit for this use case.

## Evaluation Details

### Current Model Architecture

The SMS Specialist Classifier uses:
- **Algorithm**: Logistic regression (linear model)
- **Features**: TF-IDF with word unigrams + bigrams
- **Model size**: ~205 vocabulary terms (test fixture), small JSON artifact
- **Inference**: Pure Kotlin, CPU-only, ~microseconds per message
- **Dependencies**: None beyond Kotlin stdlib

### ExecuTorch Fit Analysis

| Criterion | Assessment |
|-----------|-----------|
| Model type match | Poor — logistic regression is not a PyTorch model; ExecuTorch executes exported PyTorch graphs |
| Inference latency | Pure Kotlin logistic regression is already sub-millisecond; ExecuTorch runtime initialization would add overhead |
| Binary size impact | ExecuTorch Android runtime adds ~30-50MB to APK; unacceptable for a lightweight classifier |
| Offline capability | Supported, but pure Kotlin already satisfies this |
| ARM optimization | XNNPACK delegation available, but unnecessary for linear algebra on small vectors |
| Development complexity | High — requires PyTorch training, .pte export, runtime integration, fallback handling |

### When ExecuTorch Would Be Appropriate

ExecuTorch would be appropriate if:
1. A transformer-based model (e.g., DistilBERT, MobileBERT) is used for threat classification
2. A compact language model is used for threat explanation generation
3. Model size and latency justify the runtime overhead

### Alternative Architecture (Recommended)

The current pure-Kotlin inference pipeline is the correct architecture for this project:

```
AnalysisInput → InputNormalizer → FastRuleEngine → UrlSpecialistDetector → SmsSpecialistClassifier → RiskPolicyEngine → Verdict
```

All components run offline on CPU with no external dependencies.

### Blocker

No JDK or Android SDK is available in this environment, so ExecuTorch integration cannot be built or tested. Even if pursued, it would require:
1. PyTorch model training and export
2. ExecuTorch Android SDK dependency
3. .pte model artifact packaging
4. Kotlin runtime integration
5. Fallback to pure Kotlin when ExecuTorch is unavailable

These are out of scope for the current implementation phase.

## Recommendation

**Do not integrate ExecuTorch.** The pure-Kotlin logistic regression classifier meets all requirements:
- Offline inference ✓
- Deterministic output ✓
- Explainable via contributing features ✓
- No network dependency ✓
- Minimal binary size impact ✓
- ARM CPU compatible ✓

If a future phase requires transformer-based classification or LLM-based explanation, ExecuTorch should be re-evaluated at that time with a specific model architecture and performance budget.
