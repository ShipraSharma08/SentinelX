package com.sentinelx.core.service;

import com.sentinelx.core.dto.auth.AuthResponse;
import com.sentinelx.core.dto.auth.LoginRequest;
import com.sentinelx.core.dto.auth.RegisterRequest;
import com.sentinelx.core.model.Role;
import com.sentinelx.core.model.User;
import com.sentinelx.core.security.CustomUserDetailsService;
import com.sentinelx.core.security.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.OffsetDateTime;

@Service
public class AuthService {

    private final UserService userService;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final JwtService jwtService;

    public AuthService(
            UserService userService,
            RoleService roleService,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            CustomUserDetailsService userDetailsService,
            JwtService jwtService
    ) {
        this.userService = userService;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userService.existsByUsername(request.username())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "Username is already registered"
            );
        }

        if (userService.existsByEmail(request.email())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "Email is already registered"
            );
        }

        Role viewerRole = roleService.findByName("VIEWER")
                .orElseThrow(() -> new IllegalStateException(
                        "Required VIEWER role is missing from the database"
                ));

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(viewerRole);
        user.setActive(true);
        user.setCreatedAt(OffsetDateTime.now());

        User savedUser = userService.save(user);

        UserDetails userDetails =
                userDetailsService.loadUserByUsername(savedUser.getUsername());

        String token = jwtService.generateToken(userDetails);

        return toAuthResponse(savedUser, token);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.usernameOrEmail(),
                        request.password()
                )
        );

        User user = userService.findByUsername(request.usernameOrEmail())
                .or(() -> userService.findByEmail(request.usernameOrEmail()))
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid username/email or password"
                ));

        user.setLastLogin(OffsetDateTime.now());
        User updatedUser = userService.update(user);

        UserDetails userDetails =
                userDetailsService.loadUserByUsername(updatedUser.getUsername());

        String token = jwtService.generateToken(userDetails);

        return toAuthResponse(updatedUser, token);
    }

    private AuthResponse toAuthResponse(User user, String token) {
        return new AuthResponse(
                token,
                "Bearer",
                jwtService.getExpirationSeconds(),
                new AuthResponse.UserInfo(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        user.getRole().getName()
                )
        );
    }
}
