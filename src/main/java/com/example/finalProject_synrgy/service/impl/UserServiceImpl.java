package com.example.finalProject_synrgy.service.impl;

import lombok.extern.slf4j.Slf4j;
import com.example.finalProject_synrgy.dto.UserRequest;
import com.example.finalProject_synrgy.dto.UserResponse;
import com.example.finalProject_synrgy.entity.oauth2.EmailConfirmationToken;
import com.example.finalProject_synrgy.entity.oauth2.User;
import com.example.finalProject_synrgy.mapper.UserMapper;
import com.example.finalProject_synrgy.repository.EmailConfirmationTokenRepository;
import com.example.finalProject_synrgy.repository.UserRepository;
import com.example.finalProject_synrgy.service.EmailService;
import com.example.finalProject_synrgy.service.UserService;
import com.example.finalProject_synrgy.service.ValidationService;
import com.google.api.client.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import javax.mail.MessagingException;
import javax.persistence.criteria.Predicate;

import java.nio.charset.Charset;
import java.security.Principal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ValidationService validationService;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private EmailService emailService;

    @Autowired
    private EmailConfirmationTokenRepository emailConfirmationTokenRepository;

    private static final BytesKeyGenerator DEFAULT_TOKEN_GENERATOR = KeyGenerators.secureRandom(15);

    private static final Charset US_ASCII = Charset.forName("US-ASCII");

    @Override
    public UserResponse create(UserRequest userRequest) {
        validationService.validate(userRequest);
        User user = new User();
        user.setUsername(userRequest.getUsername());
        user.setEmailAddress(userRequest.getEmailAddress());
        user.setPassword(encoder.encode(userRequest.getPassword()));
    
        if (userRepository.existsByEmailAddress(userRequest.getEmailAddress())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already exist");
        }
    
        if (userRepository.existsByUsername(userRequest.getUsername())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username already exist");
        }
        userRepository.save(user);
    
        try {
            sendRegistrationConfirmationEmail(user);
        } catch (MessagingException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to send verification email");
        }
    
        return userMapper.toUserResponse(user);
    }
    

    @Override
    public List<UserResponse> findAll(Pageable pageable, String username, String emailAddress) {
        Specification<User> spec = ((root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (username != null && !username.isEmpty()) {
                predicates.add(criteriaBuilder.like(criteriaBuilder.lower(root.get("username")),
                        "%" + username.toLowerCase() + "%"));
            }
            if (emailAddress != null && !emailAddress.isEmpty()) {
                predicates.add(criteriaBuilder.like(criteriaBuilder.lower(root.get("emailAddress")),
                        "%" + emailAddress.toLowerCase() + "%"));
            }
            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        });
        List<UserResponse> response = new ArrayList<UserResponse>();
        userRepository.findAll(spec, pageable).forEach(user -> {
            log.info("USER : {}", user);
            response.add(userMapper.toUserResponse(user));
        });
        return response;
    }

    @Override
    @Transactional
    public UserResponse update(Principal principal, UserRequest request) {
        validationService.validate(request);
        log.info("REQUEST : {}", request);
        User user = userRepository.findByUsername(principal.getName());

        if (userRepository.existsByEmailAddress(request.getEmailAddress())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already exist");
        }

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username already exist");
        }

        if (Objects.nonNull(request.getUsername())) {
            user.setUsername(request.getUsername());
        }

        if (Objects.nonNull(request.getEmailAddress())) {
            user.setEmailAddress(request.getEmailAddress());
        }

        if (Objects.nonNull(request.getPassword())) {
            user.setPassword(encoder.encode(request.getPassword()));
        }

        userRepository.save(user);

        return userMapper.toUserResponse(user);
    }

    @Override
    @Transactional
    public UserResponse delete(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "ID User not found"));
        userRepository.delete(user);

        return userMapper.toUserResponse(user);
    }

    @Override
    public UserResponse findById(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "ID User not found"));
        return userMapper.toUserResponse(user);
    }

    @Override
    public void sendRegistrationConfirmationEmail(User user) throws MessagingException {
        // Generate the token
        String tokenValue = new String(Base64.encodeBase64URLSafe(DEFAULT_TOKEN_GENERATOR.generateKey()),
                US_ASCII);
        EmailConfirmationToken emailConfirmationToken = new EmailConfirmationToken();
        emailConfirmationToken.setToken(tokenValue);
        emailConfirmationToken.setTimeStamp(LocalDateTime.now());
        emailConfirmationToken.setUser(user);
        emailConfirmationTokenRepository.save(emailConfirmationToken);
    
        // Log before sending email
        log.info("Sending verification email to: {}", user.getEmailAddress());
    
        // Send email
        emailService.sendConfirmationEmail(emailConfirmationToken);
    
        // Log after sending email
        log.info("Verification email sent to: {}", user.getEmailAddress());
    }
    

    @Override
    public boolean verifyUser(String token) throws InvalidTokenException {
        EmailConfirmationToken emailConfirmationToken = emailConfirmationTokenRepository.findByToken(token);
        if (emailConfirmationToken == null) {
            return false;
        }
        User user = emailConfirmationToken.getUser();
        if (user.isEnabled()) {
            return false; // Token sudah pernah diverifikasi
        }
        user.setEnabled(true);
        userRepository.save(user);
        return true;
    }
}
