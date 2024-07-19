package com.example.finalProject_synrgy.service;

import com.example.finalProject_synrgy.dto.UserRequest;
import com.example.finalProject_synrgy.dto.UserResponse;
import com.example.finalProject_synrgy.entity.oauth2.User;

import org.springframework.data.domain.Pageable;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.security.Principal;
import java.util.List;
import java.util.UUID;

import javax.mail.MessagingException;

public interface UserService {

    UserResponse create(UserRequest userRequest);

    List<UserResponse> findAll(Pageable pageable, String username, String emailAddress);

    UserResponse update(Principal principal, UserRequest request);

    UserResponse delete(UUID id);

    UserResponse findById(UUID id);

    void sendRegistrationConfirmationEmail(final User user) throws MessagingException;

    boolean verifyUser(final String token) throws InvalidTokenException;
}
