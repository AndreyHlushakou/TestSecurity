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
@Table(name = "black_list_refresh_token")
@DynamicInsert
@DynamicUpdate
@Getter
@Setter
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class BlackListRefreshTokenEntity {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.UUID)
    UUID id;

    @Column(name = "refresh_token")
    String refreshToken;

    @Column(name = "expiration")
    ZonedDateTime expiration;

}
