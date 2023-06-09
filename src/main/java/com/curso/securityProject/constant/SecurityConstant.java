package com.curso.securityProject.constant;

public class SecurityConstant {
    public static final long EXPIRATION_TIME = 432000000; //5days in milliseconds
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token"; //nos creamos un custom header. request
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String CARLOS_COLLAGUAZO = "Carlos Collaguazo";
    public static final String GET_CARLOS_ADMINSTRATION = "User Management Portal";
    public static final String AUTHORITIES = "authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to login to access this page";
    public static final String ACCESS_DENIED_MESSAGE = "You dont have permission to access this page";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
    //public static final String[] PUBLIC_URLS = {"/user/login", "/user/register", "/user/resetpassword/**", "/user/image/**" };
    public static final String[] PUBLIC_URLS = {"**"};
}
