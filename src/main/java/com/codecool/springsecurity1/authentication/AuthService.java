package com.codecool.springsecurity1.authentication;

import com.codecool.springsecurity1.config.JwtService;
import com.codecool.springsecurity1.repo.UserRepository;
import com.codecool.springsecurity1.user.RoleType;
import com.codecool.springsecurity1.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    public String register(RegisterRequest request) {
        User user = User.builder()
                .username(request.getUsername())
                .password(encoder.encode(request.getPassword()))
                .email(request.getEmail())
                .roleType(RoleType.ADMIN)
                .build();
        userRepository.save(user);

        return jwtService.generateToken(user);
    }

    public String authenticate(AuthRequest authRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
        );
        User user = userRepository.findByUsername(authRequest.getUsername()).orElseThrow(() -> new UsernameNotFoundException("Username not found."));
        return jwtService.generateToken(user);
    }

}
