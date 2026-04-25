package com.antivirus.license;

import com.antivirus.license.dto.ActivateLicenseRequest;
import com.antivirus.license.dto.CheckLicenseRequest;
import com.antivirus.license.dto.CreateLicenseRequest;
import com.antivirus.license.dto.CreateLicenseResponse;
import com.antivirus.license.dto.RenewLicenseRequest;
import com.antivirus.ticket.TicketResponse;
import com.antivirus.user.UserEntity;
import com.antivirus.user.UserRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/licenses")
public class LicenseController {

    private final LicenseService licenseService;
    private final UserRepository userRepository;

    public LicenseController(LicenseService licenseService, UserRepository userRepository) {
        this.licenseService = licenseService;
        this.userRepository = userRepository;
    }

    @PostMapping
    public ResponseEntity<CreateLicenseResponse> create(@Valid @RequestBody CreateLicenseRequest req,
                                                        Authentication auth) {
        LicenseEntity license = licenseService.createLicense(
                req.productId(), req.typeId(), req.ownerId(), req.deviceCount(), req.description());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new CreateLicenseResponse(license.getId(), license.getCode()));
    }

    @PostMapping("/activate")
    public ResponseEntity<TicketResponse> activate(@Valid @RequestBody ActivateLicenseRequest req,
                                                   Authentication auth) {
        Long userId = resolveUserId(auth);
        TicketResponse response = licenseService.activateLicense(
                req.activationKey(), req.deviceMac(), req.deviceName(), userId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/check")
    public ResponseEntity<TicketResponse> check(@Valid @RequestBody CheckLicenseRequest req,
                                                Authentication auth) {
        Long userId = resolveUserId(auth);
        TicketResponse response = licenseService.checkLicense(req.productId(), req.deviceMac(), userId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/renew")
    public ResponseEntity<TicketResponse> renew(@Valid @RequestBody RenewLicenseRequest req,
                                                Authentication auth) {
        Long userId = resolveUserId(auth);
        TicketResponse response = licenseService.renewLicense(req.activationKey(), userId);
        return ResponseEntity.ok(response);
    }

    private Long resolveUserId(Authentication auth) {
        String username = auth.getName();
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        return user.getId();
    }
}
