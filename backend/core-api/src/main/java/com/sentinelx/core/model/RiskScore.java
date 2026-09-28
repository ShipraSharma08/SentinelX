package com.sentinelx.core.model;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.OffsetDateTime;

@Entity
@Table(name = "risk_scores")
public class RiskScore {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "alert_id")
    private Long alertId;

    @Column(name = "incident_id")
    private Long incidentId;

    @Column(name = "sequence_id")
    private Long sequenceId;

    @Column(nullable = false, precision = 5, scale = 2)
    private BigDecimal score;

    @Column(name = "risk_level", nullable = false, length = 20)
    private String riskLevel;

    @Column(name = "scoring_method", length = 100)
    private String scoringMethod;

    @Column(columnDefinition = "TEXT")
    private String explanation;

    @Column(name = "calculated_at", nullable = false)
    private OffsetDateTime calculatedAt;

    public RiskScore() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getAlertId() {
        return alertId;
    }

    public void setAlertId(Long alertId) {
        this.alertId = alertId;
    }

    public Long getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(Long incidentId) {
        this.incidentId = incidentId;
    }

    public Long getSequenceId() {
        return sequenceId;
    }

    public void setSequenceId(Long sequenceId) {
        this.sequenceId = sequenceId;
    }

    public BigDecimal getScore() {
        return score;
    }

    public void setScore(BigDecimal score) {
        this.score = score;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getScoringMethod() {
        return scoringMethod;
    }

    public void setScoringMethod(String scoringMethod) {
        this.scoringMethod = scoringMethod;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public OffsetDateTime getCalculatedAt() {
        return calculatedAt;
    }

    public void setCalculatedAt(OffsetDateTime calculatedAt) {
        this.calculatedAt = calculatedAt;
    }
}
