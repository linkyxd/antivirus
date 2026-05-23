package com.antivirus.ticket;

import com.antivirus.signature.SignatureService;
import org.springframework.stereotype.Service;

/**
 * Тонкая обёртка над {@link SignatureService}, формирующая ответ с подписью для лицензии.
 *
 * <p>Логика канонизации и криптографии вынесена в модуль ЭЦП ({@code com.antivirus.signature}).
 * Этот сервис только связывает доменную модель {@link Ticket} и инфраструктурный
 * {@link SignatureService}.</p>
 */
@Service
public class TicketSigningService {

    private final SignatureService signatureService;

    public TicketSigningService(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    public TicketResponse sign(Ticket ticket) {
        String digitalSignature = signatureService.sign(ticket);
        return new TicketResponse(ticket, digitalSignature);
    }
}
