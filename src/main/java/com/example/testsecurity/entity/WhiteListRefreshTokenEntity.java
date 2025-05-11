package com.example.testsecurity.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import java.time.ZonedDateTime;
import java.util.UUID;

@Entity
@Table(name = "white_list_refresh_token")
@DynamicInsert
@DynamicUpdate
@Getter
@Setter
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class WhiteListRefreshTokenEntity {

    @Id
    @Column(name = "id")
    UUID id;

    @Column(name = "refresh_token")
    String refreshToken;

    @Column(name = "expiration")
    ZonedDateTime expiration;

    public WhiteListRefreshTokenEntity(UUID id) {
        this.id = id;
    }

}
