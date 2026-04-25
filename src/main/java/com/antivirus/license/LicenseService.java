package com.antivirus.license;

import com.antivirus.device.DeviceEntity;
import com.antivirus.device.DeviceRepository;
import com.antivirus.device.DeviceService;
import com.antivirus.product.ProductEntity;
import com.antivirus.product.ProductService;
import com.antivirus.ticket.Ticket;
import com.antivirus.ticket.TicketResponse;
import com.antivirus.ticket.TicketSigningService;
import com.antivirus.user.UserEntity;
import com.antivirus.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class LicenseService {

    private static final long TICKET_LIFETIME_SECONDS = 600;

    private final LicenseRepository licenseRepository;
    private final LicenseTypeRepository licenseTypeRepository;
    private final DeviceLicenseRepository deviceLicenseRepository;
    private final LicenseHistoryRepository licenseHistoryRepository;
    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final ProductService productService;
    private final DeviceService deviceService;
    private final TicketSigningService ticketSigningService;

    public LicenseService(LicenseRepository licenseRepository,
                          LicenseTypeRepository licenseTypeRepository,
                          DeviceLicenseRepository deviceLicenseRepository,
                          LicenseHistoryRepository licenseHistoryRepository,
                          UserRepository userRepository,
                          DeviceRepository deviceRepository,
                          ProductService productService,
                          DeviceService deviceService,
                          TicketSigningService ticketSigningService) {
        this.licenseRepository = licenseRepository;
        this.licenseTypeRepository = licenseTypeRepository;
        this.deviceLicenseRepository = deviceLicenseRepository;
        this.licenseHistoryRepository = licenseHistoryRepository;
        this.userRepository = userRepository;
        this.deviceRepository = deviceRepository;
        this.productService = productService;
        this.deviceService = deviceService;
        this.ticketSigningService = ticketSigningService;
    }

    @Transactional
    public LicenseEntity createLicense(Long productId, Long typeId, Long ownerId,
                                       int deviceCount, String description) {
        ProductEntity product = productService.getProductOrFail(productId);
        LicenseTypeEntity type = licenseTypeRepository.findById(typeId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "License type not found: " + typeId));
        UserEntity owner = userRepository.findById(ownerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found: " + ownerId));

        LicenseEntity license = new LicenseEntity();
        license.setCode(UUID.randomUUID().toString());
        license.setProduct(product);
        license.setType(type);
        license.setOwner(owner);
        license.setDeviceCount(deviceCount);
        license.setDescription(description);

        license = licenseRepository.save(license);

        addHistory(license, owner, "CREATED", "License created");

        return license;
    }

    @Transactional
    public TicketResponse activateLicense(String activationKey, String deviceMac,
                                          String deviceName, Long userId) {
        LicenseEntity license = licenseRepository.findByCode(activationKey)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "License not found"));

        if (license.isBlocked()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "License is blocked");
        }
        if (license.getProduct().isBlocked()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Product is blocked");
        }

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        DeviceEntity device = deviceService.findOrCreateDevice(deviceMac, deviceName, user);

        boolean isFirstActivation = license.getFirstActivationDate() == null;

        if (isFirstActivation) {
            int durationDays = license.getType().getDefaultDurationInDays();
            Instant now = Instant.now();
            license.setFirstActivationDate(now);
            license.setEndingDate(now.plus(durationDays, ChronoUnit.DAYS));
            license.setUser(user);
        } else {
            long currentDevices = deviceLicenseRepository.countByLicense(license);
            if (currentDevices >= license.getDeviceCount()) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Device limit reached for this license");
            }
        }

        DeviceLicenseEntity dl = new DeviceLicenseEntity();
        dl.setLicense(license);
        dl.setDevice(device);
        dl.setActivationDate(Instant.now());
        deviceLicenseRepository.save(dl);

        licenseRepository.save(license);
        addHistory(license, user, "ACTIVATED", "Activated on device " + deviceMac);

        return buildTicketResponse(license, user.getId(), device.getId());
    }

    @Transactional(readOnly = true)
    public TicketResponse checkLicense(Long productId, String deviceMac, Long userId) {
        DeviceEntity device = deviceRepository.findByMacAddress(deviceMac)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Device not found"));

        LicenseEntity license = licenseRepository
                .findActiveByDeviceUserAndProduct(device.getId(), userId, productId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No active license found for this device and product"));

        return buildTicketResponse(license, userId, device.getId());
    }

    @Transactional
    public TicketResponse renewLicense(String activationKey, Long userId) {
        LicenseEntity license = licenseRepository.findByCode(activationKey)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "License not found"));

        if (license.isBlocked()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "License is blocked");
        }

        Instant now = Instant.now();
        Instant ending = license.getEndingDate();

        if (ending == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "License has not been activated yet");
        }

        boolean expired = ending.isBefore(now);
        boolean nearExpiry = !expired && ending.isBefore(now.plus(7, ChronoUnit.DAYS));

        if (!expired && !nearExpiry) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "License is not eligible for renewal yet");
        }

        int durationDays = license.getType().getDefaultDurationInDays();
        Instant newEnding = (expired ? now : ending).plus(durationDays, ChronoUnit.DAYS);
        license.setEndingDate(newEnding);
        licenseRepository.save(license);

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        addHistory(license, user, "RENEWED", "License renewed");

        return buildTicketResponse(license, userId, null);
    }

    private TicketResponse buildTicketResponse(LicenseEntity license, Long userId, Long deviceId) {
        Ticket ticket = new Ticket(
                Instant.now(),
                TICKET_LIFETIME_SECONDS,
                license.getFirstActivationDate(),
                license.getEndingDate(),
                userId,
                deviceId,
                license.isBlocked()
        );
        return ticketSigningService.sign(ticket);
    }

    private void addHistory(LicenseEntity license, UserEntity user, String status, String description) {
        LicenseHistoryEntity h = new LicenseHistoryEntity();
        h.setLicense(license);
        h.setUser(user);
        h.setStatus(status);
        h.setChangeDate(Instant.now());
        h.setDescription(description);
        licenseHistoryRepository.save(h);
    }
}
