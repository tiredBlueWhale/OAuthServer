package com.patternpedia.auth.user.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.patternpedia.auth.user.entities.Role;
import com.sun.istack.NotNull;
import com.vladmihalcea.hibernate.type.basic.PostgreSQLEnumType;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.annotations.NaturalId;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;

import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Entity
@Data
@NoArgsConstructor
public class UserEntity implements Serializable {

    @Id
    @GeneratedValue(generator = "pg-uuid")
    private UUID id;

    @JsonIgnore
    @ToString.Exclude
    @ManyToOne()
    private Role role;

    @NaturalId(mutable = true)
    @Column(nullable = false, unique = true)
    private String email;

    @NaturalId(mutable = true)
    @Column(nullable = false, unique = true)
    private String name;

    @JsonIgnore
    @Column(nullable = false)
    private String password;

    public UserEntity(String name, String email, String password, Role role) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
    }

}
