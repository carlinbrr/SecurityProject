package com.curso.securityProject.service;



import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import javax.mail.internet.MimeMessage;



@Service
@RequiredArgsConstructor
public class EmailService {
    public static final String NEW_USER_ACCOUNT_PASSWORD = "New User Account Password";
    private final JavaMailSender emailSender;
    private String fromEmail="carlosdev050@gmail.com";

    public void sendPassword(String name, String to, String password) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setSubject(NEW_USER_ACCOUNT_PASSWORD);
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setText(getEmailMessage(name, password));
            emailSender.send(message);
        } catch (Exception exception) {
            System.out.println(exception.getMessage());
            throw new RuntimeException(exception.getMessage());
        }
    }

    private MimeMessage getMimeMessage() {
        return emailSender.createMimeMessage();
    }

    private String getContentId(String filename) {
        return "<" + filename + ">";
    }

    public static String getEmailMessage(String name, String password) {
        return "Hello " + name + ",\n\nYour password for the system is: " + password;
    }

}