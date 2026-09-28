package com.sentinelx.core.model;

import jakarta.persistence.*;
import java.io.Serializable;
import java.time.OffsetDateTime;

@Entity
@Table(
    name = "attack_sequence_events",
    uniqueConstraints = {
        @UniqueConstraint(
            name = "uk_attack_sequence_events_order",
            columnNames = {"sequence_id", "sequence_order"}
        )
    }
)
public class AttackSequenceEvent {

    @EmbeddedId
    private AttackSequenceEventId id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @MapsId("sequenceId")
    @JoinColumn(name = "sequence_id", nullable = false)
    private AttackSequence sequence;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @MapsId("eventId")
    @JoinColumn(name = "event_id", nullable = false)
    private SecurityEvent event;

    @Column(name = "sequence_order", nullable = false)
    private Integer sequenceOrder;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    public AttackSequenceEvent() {
    }

    public AttackSequenceEventId getId() {
        return id;
    }

    public void setId(AttackSequenceEventId id) {
        this.id = id;
    }

    public AttackSequence getSequence() {
        return sequence;
    }

    public void setSequence(AttackSequence sequence) {
        this.sequence = sequence;
    }

    public SecurityEvent getEvent() {
        return event;
    }

    public void setEvent(SecurityEvent event) {
        this.event = event;
    }

    public Integer getSequenceOrder() {
        return sequenceOrder;
    }

    public void setSequenceOrder(Integer sequenceOrder) {
        this.sequenceOrder = sequenceOrder;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }

    @Embeddable
    public static class AttackSequenceEventId implements Serializable {

        private Long sequenceId;
        private Long eventId;

        public AttackSequenceEventId() {
        }

        public AttackSequenceEventId(Long sequenceId, Long eventId) {
            this.sequenceId = sequenceId;
            this.eventId = eventId;
        }

        public Long getSequenceId() {
            return sequenceId;
        }

        public void setSequenceId(Long sequenceId) {
            this.sequenceId = sequenceId;
        }

        public Long getEventId() {
            return eventId;
        }

        public void setEventId(Long eventId) {
            this.eventId = eventId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof AttackSequenceEventId)) return false;

            AttackSequenceEventId that = (AttackSequenceEventId) o;

            return java.util.Objects.equals(sequenceId, that.sequenceId)
                    && java.util.Objects.equals(eventId, that.eventId);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(sequenceId, eventId);
        }
    }
}
