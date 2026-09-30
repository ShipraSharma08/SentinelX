package com.sentinelx.core.model;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

@Entity
@Table(name = "threat_indicators")
public class ThreatIndicator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "indicator_type", nullable = false, length = 30)
    private String indicatorType;

    @Column(name = "indicator_value", nullable = false, length = 500)
    private String indicatorValue;

    @Column(name = "threat_type", length = 100)
    private String threatType;

    @Column(nullable = false, length = 20)
    private String confidence;

    @Column(length = 255)
    private String source;

    @Column(name = "first_seen")
    private OffsetDateTime firstSeen;

    @Column(name = "last_seen")
    private OffsetDateTime lastSeen;

    @Column(name = "is_active", nullable = false)
    private boolean active;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    public ThreatIndicator() {
    }

    public Long getId() {
        return id;
    }

    public String getIndicatorType() {
        return indicatorType;
    }

    public void setIndicatorType(String indicatorType) {
        this.indicatorType = indicatorType;
    }

    public String getIndicatorValue() {
        return indicatorValue;
    }

    public void setIndicatorValue(String indicatorValue) {
        this.indicatorValue = indicatorValue;
    }

    public String getThreatType() {
        return threatType;
    }

    public void setThreatType(String threatType) {
        this.threatType = threatType;
    }

    public String getConfidence() {
        return confidence;
    }

    public void setConfidence(String confidence) {
        this.confidence = confidence;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public OffsetDateTime getFirstSeen() {
        return firstSeen;
    }

    public void setFirstSeen(OffsetDateTime firstSeen) {
        this.firstSeen = firstSeen;
    }

    public OffsetDateTime getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(OffsetDateTime lastSeen) {
        this.lastSeen = lastSeen;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }
}