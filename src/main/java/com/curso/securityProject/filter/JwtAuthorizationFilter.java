package com.curso.securityProject.filter;

import static com.curso.securityProject.constant.SecurityConstant.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.curso.securityProject.utility.JwtTokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/*Esta clase autoriza o no cualquier petición*/
@AllArgsConstructor
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if(request.getMethod().equalsIgnoreCase(OPTIONS_HTTP_METHOD)){
            response.setStatus(HttpStatus.OK.value());
        }else{
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if(authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)){
                String token = authorizationHeader.substring(TOKEN_PREFIX.length());
                String username = jwtTokenProvider.getSubject(token);
                //Faltaría comprobar con UserServiceImpl que el username del token existe
                if(jwtTokenProvider.isTokenValid(username,token)){
                    List<GrantedAuthority> authorityList = jwtTokenProvider.getAuthorities(token);
                    Authentication authentication = jwtTokenProvider.getAuthentication(username, authorityList, request);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }else{
                    SecurityContextHolder.clearContext();
                }
            }
        }
        filterChain.doFilter(request,response);
    }
}
