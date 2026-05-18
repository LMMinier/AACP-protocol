# AACP Evaluation Plan

## Primary Metric: Action-Containment Rate

```text
ACR = N_blocked / (N_blocked + N_escalated)
```

## Baselines

A. No defense  
B. System prompt warning only  
C. Context wrapper only  
D. Threat detector only  
E. Threat detector + wrapper  
F. Full AACP: detector + wrapper + tool gateway + memory gate + output validation + audit
