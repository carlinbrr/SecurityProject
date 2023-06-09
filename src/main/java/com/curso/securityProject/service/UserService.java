package com.curso.securityProject.service;

import com.curso.securityProject.domain.User;
import com.curso.securityProject.exception.domain.EmailExistException;
import com.curso.securityProject.exception.domain.EmailNotFoundException;
import com.curso.securityProject.exception.domain.UserNotFoundException;
import com.curso.securityProject.exception.domain.UsernameExistException;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface UserService {
    User register (String firstname, String lastName, String username, String email)
            throws UserNotFoundException, EmailExistException, UsernameExistException;
    List<User> getUsers();
    User findUserByEmail(String email);
    User findUserByUsername(String username);
    User findUserById(Long id) throws UserNotFoundException;
    User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked,
                    boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

    User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail,
                    String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;
    void deleteUser(Long id);
    void resetPassword(String email) throws EmailNotFoundException;
    User updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;
}
