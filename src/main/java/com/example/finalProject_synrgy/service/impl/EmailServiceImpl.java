package com.example.finalProject_synrgy.service.impl;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import com.example.finalProject_synrgy.entity.oauth2.EmailConfirmationToken;
import com.example.finalProject_synrgy.service.EmailService;

@Service
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender sender;

    public EmailServiceImpl(JavaMailSender sender) {
        this.sender = sender;
    }

    @Override
    public void sendConfirmationEmail(EmailConfirmationToken emailConfirmationToken) throws MessagingException {
        // MIME - HTML message
        MimeMessage message = sender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setTo(emailConfirmationToken.getUser().getUsername());
        helper.setSubject("Confirm you E-Mail - MFA Application Registration");
        helper.setText("<html>" +
                "<body>" +
                "<h2>Dear " + emailConfirmationToken.getUser().getUsername() + ",</h2>"
                + "<br/> We're excited to have you get started. " +
                "Please click on below link to confirm your account."
                + "<br/> " + generateConfirmationLink(emailConfirmationToken.getToken()) + "" +
                "<br/> Regards,<br/>" +
                "MFA Registration team" +
                "</body>" +
                "</html>", true);

        sender.send(message);
    }

    private String generateConfirmationLink(String token) {
        return "<a href=http://localhost:8080/confirm-email?token=" + token + ">Confirm Email</a>";
    }
}