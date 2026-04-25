package com.antivirus.ticket;

import java.time.Instant;

public record Ticket(
        Instant serverDate,
        long ticketLifetimeSeconds,
        Instant activationDate,
        Instant expirationDate,
        Long userId,
        Long deviceId,
        boolean blocked
) {
}
