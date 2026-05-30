# Local YARA overlay (lab-only)

规则的**事实来源**是仓库的 [`../../../01-hardening-checklist/detection/yara`](../../../01-hardening-checklist/detection/yara)。
`scripts\analysis\Invoke-RuleValidation.ps1`(编译校验)与 `scripts\analysis\Invoke-YaraScan.ps1`(实扫)
都可指向那里,**不复制**。

本目录只放**靶场专用**的临时/试验 YARA 规则。正式规则请提交到 `01-hardening-checklist/detection/yara`。
