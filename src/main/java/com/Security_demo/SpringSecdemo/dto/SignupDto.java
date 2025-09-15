package com.Security_demo.SpringSecdemo.dto;

import com.Security_demo.SpringSecdemo.entities.enums.Permission;
import com.Security_demo.SpringSecdemo.entities.enums.Role;
import lombok.Data;

import java.util.Set;

@Data
public class SignupDto {
    private String email;
    private String password;
    private String name;
    private Set<Role> roles;
    private Set<Permission> permissions;
}
