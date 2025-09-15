package com.Security_demo.SpringSecdemo.entities;

import com.Security_demo.SpringSecdemo.entities.enums.Permission;
import com.Security_demo.SpringSecdemo.entities.enums.Role;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String email;
    private String password;
    private String name;

    @ElementCollection(fetch = FetchType.EAGER)    // to fetch the roles eagerly
    @Enumerated(EnumType.STRING)        // if this is not added , it will store the index of the enum
    private Set<Role> roles;

    @ElementCollection(fetch = FetchType.EAGER)    // to fetch the roles eagerly
    @Enumerated(EnumType.STRING)        // if this is not added , it will store the index of the enum
    private Set<Permission> permissions;



    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<SimpleGrantedAuthority> authorities = roles.stream()
        .map(role -> new SimpleGrantedAuthority("ROLE_"+role.name()))
        .collect(Collectors.toSet());
        
        permissions.forEach(
            permission -> authorities.add(new SimpleGrantedAuthority(permission.name()))
        );

        return authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.email;
    }
}
