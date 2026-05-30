# Local Sigma overlay (lab-only)

规则的**事实来源**是仓库的 [`../../../01-hardening-checklist/detection/sigma`](../../../01-hardening-checklist/detection/sigma)。
`scripts\analysis\Invoke-RuleValidation.ps1` 直接消费那里的规则,**不复制**。

本目录只放**靶场专用**的临时/试验 Sigma 规则(例如为复现某本地行为而写的草稿)。
不要在这里复制仓库规则;正式规则请提交到 `01-hardening-checklist/detection/sigma`。
