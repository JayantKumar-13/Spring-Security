package com.Security_demo.SpringSecdemo.service;

import com.Security_demo.SpringSecdemo.dto.SignupDto;
import com.Security_demo.SpringSecdemo.dto.UserDto;
import com.Security_demo.SpringSecdemo.entities.User;
import com.Security_demo.SpringSecdemo.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.aspectj.asm.IModelFilter;
import org.modelmapper.ModelMapper;
import org.springframework.boot.Banner;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor

public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username).orElseThrow(() -> new BadCredentialsException("User with this email " + username + "not found"));
    }

    public User getUserById(Long userId) {
        return userRepository.findById(userId).orElse(null);
    }

    public User getUsrByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }


    public UserDto signUp(SignupDto signupDto) {
        Optional<User> user = userRepository.findByEmail(signupDto.getEmail());
        if(user.isPresent())
        {
            throw new BadCredentialsException("User with this email " + signupDto.getEmail() + "already exists");
        }
        User tobeCreated = modelMapper.map(signupDto , User.class);  //Mapping to the user entity
        tobeCreated.setPassword(passwordEncoder.encode(tobeCreated.getPassword()));
        User savedUser = userRepository.save(tobeCreated);
        return modelMapper.map(savedUser, UserDto.class);
    }
    public User save(User newUser) {
        return userRepository.save(newUser);
    }

    //    public String login(LoginDto loginDto){
    //        Authentication authentication = authenticationManager.authenticate(
    //            new UsernamePasswordAuthenticationToken(loginDto.getEmail() , loginDto.getPassword())
    //        );
    //        User user = (User) authentication.getPrincipal();
    //        return jwtService.generateAccessToken(user);
    //    }
    // We removed this login from here because authentication Manager is also using UserService , so will create circular dependency.
    // Rather we use AuthService to create the login request
}
