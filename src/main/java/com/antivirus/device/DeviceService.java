package com.antivirus.device;

import com.antivirus.user.UserEntity;
import org.springframework.stereotype.Service;

@Service
public class DeviceService {

    private final DeviceRepository deviceRepository;

    public DeviceService(DeviceRepository deviceRepository) {
        this.deviceRepository = deviceRepository;
    }

    public DeviceEntity findOrCreateDevice(String macAddress, String name, UserEntity user) {
        return deviceRepository.findByMacAddress(macAddress)
                .orElseGet(() -> {
                    DeviceEntity device = new DeviceEntity();
                    device.setMacAddress(macAddress);
                    device.setName(name);
                    device.setUser(user);
                    return deviceRepository.save(device);
                });
    }
}
