import math
from typing import List, Dict, Any, Optional
from ..models.schemas import SeverityLevel, SecurityFinding, VerificationStatus, ScanSummary

class RiskEngine:
    """
    Evidence-based severity scoring and CVSS v3.1 / v4.0 metric alignment.
    Calculates overall environment risk, weighted posture grades, and
    prioritizes genuine confirmed vulnerabilities over speculative findings.
    """

    # Weights by severity
    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 10.0,
        SeverityLevel.HIGH: 7.5,
        SeverityLevel.MEDIUM: 4.5,
        SeverityLevel.LOW: 2.0,
        SeverityLevel.INFORMATIONAL: 0.2,
    }

    # Weight multiplier based on verification status
    VERIFICATION_MULTIPLIERS = {
        VerificationStatus.CONFIRMED: 1.0,
        VerificationStatus.POTENTIAL: 0.65,
        VerificationStatus.INCONCLUSIVE: 0.35,
        VerificationStatus.NOT_TESTED: 0.1,
        VerificationStatus.NOT_VULNERABLE: 0.0,
    }

    @classmethod
    def calculate_cvss_score(
        cls,
        severity: SeverityLevel,
        attack_vector: str = "NETWORK",
        user_interaction: str = "NONE",
        privileges_required: str = "NONE",
        impact: str = "HIGH",
    ) -> float:
        """
        Estimate a calibrated CVSS v3.1 base score based on exploitability and impact dimensions.
        """
        base = 5.0
        if severity == SeverityLevel.CRITICAL:
            base = 9.8
        elif severity == SeverityLevel.HIGH:
            base = 8.1
        elif severity == SeverityLevel.MEDIUM:
            base = 5.8
        elif severity == SeverityLevel.LOW:
            base = 3.3
        elif severity == SeverityLevel.INFORMATIONAL:
            base = 0.0

        # Adjust for attack vector
        if attack_vector == "LOCAL":
            base = max(0.0, base - 1.2)
        elif attack_vector == "PHYSICAL":
            base = max(0.0, base - 2.5)

        # Adjust for user interaction
        if user_interaction == "REQUIRED":
            base = max(0.0, base - 0.7)

        # Adjust for privileges
        if privileges_required == "HIGH":
            base = max(0.0, base - 1.5)
        elif privileges_required == "LOW":
            base = max(0.0, base - 0.6)

        return round(min(10.0, base), 1)

    @classmethod
    def calculate_scan_summary(cls, findings: List[SecurityFinding], duration_seconds: float) -> ScanSummary:
        """
        Aggregate scan metrics into an evidence-driven ScanSummary.
        Suppressed findings and NOT_VULNERABLE items do not inflate the risk score.
        """
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0

        confirmed_count = 0
        potential_count = 0
        inconclusive_count = 0

        total_weighted_risk = 0.0

        for f in findings:
            if f.suppressed:
                continue
            if f.verificationStatus == VerificationStatus.NOT_VULNERABLE:
                continue

            # Severity counts
            if f.severity == SeverityLevel.CRITICAL:
                critical_count += 1
            elif f.severity == SeverityLevel.HIGH:
                high_count += 1
            elif f.severity == SeverityLevel.MEDIUM:
                medium_count += 1
            elif f.severity == SeverityLevel.LOW:
                low_count += 1
            elif f.severity == SeverityLevel.INFORMATIONAL:
                info_count += 1

            # Verification status counts
            if f.verificationStatus == VerificationStatus.CONFIRMED:
                confirmed_count += 1
            elif f.verificationStatus == VerificationStatus.POTENTIAL:
                potential_count += 1
            elif f.verificationStatus == VerificationStatus.INCONCLUSIVE:
                inconclusive_count += 1

            # Weighted impact calculation
            weight = cls.SEVERITY_WEIGHTS.get(f.severity, 1.0)
            multiplier = cls.VERIFICATION_MULTIPLIERS.get(f.verificationStatus, 0.5)
            confidence = max(0.1, min(1.0, f.confidence))
            
            # Non-linear asymptotic risk contribution
            finding_impact = weight * multiplier * confidence
            total_weighted_risk += finding_impact

        # Normalize score into 0.0 - 100.0 scale using logistic dampening
        # 0 findings -> 0.0
        # 1 Critical -> ~35-40
        # Multiple Criticals / Highs -> asymptotically approaches 100
        if total_weighted_risk == 0:
            normalized_score = 0.0
        else:
            normalized_score = round(100.0 * (1.0 - math.exp(-total_weighted_risk / 20.0)), 1)

        return ScanSummary(
            totalFindings=len(findings),
            confirmedCount=confirmed_count,
            potentialCount=potential_count,
            inconclusiveCount=inconclusive_count,
            criticalCount=critical_count,
            highCount=high_count,
            mediumCount=medium_count,
            lowCount=low_count,
            infoCount=info_count,
            riskScore=normalized_score,
            durationSeconds=round(duration_seconds, 2),
        )

    @staticmethod
    def get_posture_grade(risk_score: float) -> str:
        """Translate risk score (0-100) into security posture grade."""
        if risk_score <= 10.0:
            return "A+ (EXCELLENT)"
        elif risk_score <= 25.0:
            return "A (STRONG DEFENSE)"
        elif risk_score <= 45.0:
            return "B (MODERATE RISK)"
        elif risk_score <= 65.0:
            return "C (ELEVATED RISK)"
        elif risk_score <= 85.0:
            return "D (HIGH RISK)"
        else:
            return "F (CRITICAL COMPROMISE RISK)"
