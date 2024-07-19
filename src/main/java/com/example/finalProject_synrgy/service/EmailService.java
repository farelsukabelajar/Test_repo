package com.example.finalProject_synrgy.service;

import javax.mail.MessagingException;

import com.example.finalProject_synrgy.entity.oauth2.EmailConfirmationToken;

public interface EmailService {
    void sendConfirmationEmail(EmailConfirmationToken emailConfirmationToken) throws MessagingException;
}