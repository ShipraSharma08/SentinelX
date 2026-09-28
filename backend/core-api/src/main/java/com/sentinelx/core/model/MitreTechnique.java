package com.sentinelx.core.model;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

@Entity
@Table(name = "mitre_techniques")
public class MitreTechnique {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "technique_id", nullable = false, unique = true, length = 50)
    private String techniqueId;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(length = 100)
    private String tactic;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    public MitreTechnique() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTechniqueId() {
        return techniqueId;
    }

    public void setTechniqueId(String techniqueId) {
        this.techniqueId = techniqueId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getTactic() {
        return tactic;
    }

    public void setTactic(String tactic) {
        this.tactic = tactic;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
