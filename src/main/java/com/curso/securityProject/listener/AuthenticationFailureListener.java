package com.curso.securityProject.listener;

import com.curso.securityProject.service.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import java.util.concurrent.ExecutionException;

@Component
public class AuthenticationFailureListener {

    @Autowired
    private LoginAttemptService loginAttemptService;
    //Se crea este listener que espera que se lance este evento
    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        if(principal instanceof String ){
            String username = (String) event.getAuthentication().getPrincipal();
            loginAttemptService.addUserLoginAttemptCache(username);
        }
    }

}
