package com.sentinelx.core.model;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_type", nullable = false, length = 100)
    private String eventType;

    @Column(nullable = false, length = 20)
    private String severity;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "source_asset_id")
    private Asset sourceAsset;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "destination_asset_id")
    private Asset destinationAsset;

    @JdbcTypeCode(SqlTypes.INET)
    @Column(name = "source_ip")
    private String sourceIp;

    @JdbcTypeCode(SqlTypes.INET)
    @Column(name = "destination_ip")
    private String destinationIp;

    @Column(name = "source_port")
    private Integer sourcePort;

    @Column(name = "destination_port")
    private Integer destinationPort;

    @Column(length = 20)
    private String protocol;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "detected_at", nullable = false)
    private OffsetDateTime detectedAt;


    // No-argument constructor
    public SecurityEvent() {
    }


    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Asset getSourceAsset() {
        return sourceAsset;
    }

    public void setSourceAsset(Asset sourceAsset) {
        this.sourceAsset = sourceAsset;
    }

    public Asset getDestinationAsset() {
        return destinationAsset;
    }

    public void setDestinationAsset(Asset destinationAsset) {
        this.destinationAsset = destinationAsset;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public void setDestinationIp(String destinationIp) {
        this.destinationIp = destinationIp;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(Integer sourcePort) {
        this.sourcePort = sourcePort;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(Integer destinationPort) {
        this.destinationPort = destinationPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public OffsetDateTime getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(OffsetDateTime detectedAt) {
        this.detectedAt = detectedAt;
    }
}