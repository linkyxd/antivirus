package com.antivirus.ticket;

public record TicketResponse(
        Ticket ticket,
        String digitalSignature
) {
}
