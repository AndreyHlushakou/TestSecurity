package com.example.testsecurity.service.impl;

import com.example.testsecurity.entity.BlackListRefreshTokenEntity;
import com.example.testsecurity.repository.BlackListRefreshTokenRepository;
import com.example.testsecurity.service.TaskDeleteRefreshTokenService;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.TimerTask;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@Service
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class TaskDeleteRefreshTokenServiceImpl implements TaskDeleteRefreshTokenService {

    BlackListRefreshTokenRepository blackListRefreshTokenRepository;

    @NonFinal
    static Consumer<UUID> consumer;

    public TaskDeleteRefreshTokenServiceImpl(BlackListRefreshTokenRepository blackListRefreshTokenRepository) {
        this.blackListRefreshTokenRepository = blackListRefreshTokenRepository;
        consumer = blackListRefreshTokenRepository::deleteById;
    }

    @PostConstruct
    public void initTasks() {
        for (BlackListRefreshTokenEntity blackListRefreshTokenEntity : blackListRefreshTokenRepository.findAll()) {
            createTask(blackListRefreshTokenEntity);
        }
    }

    @Override
    public boolean existsByRefreshToken(String refreshToken) {
        return blackListRefreshTokenRepository.existsByRefreshToken(refreshToken);
    }

    @Override
    public void addToBlackListAndAndCreateTask(BlackListRefreshTokenEntity blackListRefreshTokenEntity) {
        blackListRefreshTokenRepository.save(blackListRefreshTokenEntity);

        createTask(blackListRefreshTokenEntity);
    }

    private static void createTask(BlackListRefreshTokenEntity blackListRefreshTokenEntity) {
        ZonedDateTime dateTimeTo = blackListRefreshTokenEntity.getExpiration();
        ZonedDateTime now = ZonedDateTime.now();
        long diff = dateTimeTo.toEpochSecond() - now.toEpochSecond();
        long delay = (diff) < 0 ? 0 : diff;

        TimerTask timerTask = new TimerTask() {
            @Override
            public void run() {
                UUID uuid = blackListRefreshTokenEntity.getId();
                consumer.accept(uuid);
            }
        };

        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        executor.schedule(timerTask, delay, TimeUnit.SECONDS);
    }


}
