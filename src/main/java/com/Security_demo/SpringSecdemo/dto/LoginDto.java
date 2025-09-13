package com.Security_demo.SpringSecdemo.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class LoginDto {
    String email;
    String password;
}
