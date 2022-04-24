package com.github.klefstad_teaching.cs122b.idm.rest;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.model.request.LoginRequestModel;
import com.github.klefstad_teaching.cs122b.idm.model.response.AuthenticateResponseModel;
import com.github.klefstad_teaching.cs122b.idm.model.response.LoginResponseModel;
import com.github.klefstad_teaching.cs122b.idm.model.response.RegisterResponseModel;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.util.Validate;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;
import java.util.regex.Pattern;

@RestController
public class    IDMController
{
    private final IDMAuthenticationManager authManager;
    private final IDMJwtManager            jwtManager;
    private final Validate                 validate;

    @Autowired
    public IDMController(IDMAuthenticationManager authManager,
                         IDMJwtManager jwtManager,
                         Validate validate)
    {
        this.authManager = authManager;
        this.jwtManager = jwtManager;
        this.validate = validate;
    }
    // all input, output, result
    private void validateEmail(String email)
    {
        if (! Pattern.matches("[A-Za-z0-9]+@[A-Za-z0-9]+\\.[A-Za-z0-9]+", email))
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
        if (email.length() > 32 || email.length() < 6)
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH);
    }
    private void validatePassword(String password)
    {
        if (! Pattern.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])$", password))
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
        if (password.length() > 20 || password.length() < 10)
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseModel> login(
            @RequestBody LoginRequestModel request) throws BadJOSEException, JOSEException {
        // Input validate here, throw error
        validateEmail(request.getEmail());
        validatePassword(request.getPassword().toString());
        User user = authManager.selectAndAuthenticateUser(request.getEmail(), request.getPassword());
        authManager.repo.insertUser(user.getEmail(), user.getUserStatus().id(), user.getSalt(), user.getHashedPassword());
        LoginResponseModel response = new LoginResponseModel();
        response.setAccessToken(jwtManager.buildAccessToken(user));
        response.setRefreshToken(jwtManager.buildRefreshToken(user.getId()).getToken());
        response.setResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY);

        return response.toResponse();
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponseModel> register(
            @RequestBody LoginRequestModel request) throws BadJOSEException, JOSEException {
        // Input validate here, throw error
        validateEmail(request.getEmail());
        validatePassword(request.getPassword().toString());
        authManager.createAndInsertUser(request.getEmail(), request.getPassword());
        RegisterResponseModel response = new RegisterResponseModel();
        response.setResult(IDMResults.USER_REGISTERED_SUCCESSFULLY);

        return response.toResponse();
    }

    private void validateRefreshToken(String token)
    {
        if (token.length() != 36)
            throw new ResultError(IDMResults.REFRESH_TOKEN_HAS_INVALID_LENGTH);
        try{
            UUID uuid = UUID.fromString(token);
        } catch (IllegalArgumentException e){
            throw new ResultError(IDMResults.REFRESH_TOKEN_HAS_INVALID_FORMAT);
        }
    }
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseModel> refresh(
            @RequestParam("refreshToken")String refreshToken) throws BadJOSEException, JOSEException {
        // Input validate here, throw error
        validateRefreshToken(refreshToken);
        RefreshToken token = authManager.verifyRefreshToken(refreshToken);
        if (token.getTokenStatus() == TokenStatus.fromId(2))
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_EXPIRED);
        // DOUBLE CHECK HERE!!!
        if (token.getTokenStatus() == TokenStatus.fromId(3))
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_REVOKED);
        if (jwtManager.hasExpired(token) || token.getExpireTime().toInstant().isAfter(token.getMaxLifeTime().toInstant()))
        {
            authManager.expireRefreshToken(token);
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_EXPIRED);
        }
        // Update expire time
        jwtManager.updateRefreshTokenExpireTime(token);
        LoginResponseModel response = new LoginResponseModel();
        response.setAccessToken(jwtManager.buildAccessToken(authManager.repo.searchById(token.getUserId())));
        if (token.getExpireTime().toInstant().isAfter(token.getMaxLifeTime().toInstant()))
        {
            // revoke
            authManager.revokeRefreshToken(token);
            response.setRefreshToken(jwtManager.buildRefreshToken(token.getId()).getToken());
            response.setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN);
            return response.toResponse();
        }

        // update table
        authManager.updateRefreshTokenExpireTime(token); // repo
        response.setRefreshToken(token.getToken());
        response.setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN);

        return response.toResponse();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<LoginResponseModel> authenticate(
            @RequestParam("accessToken")String accessToken) throws BadJOSEException, JOSEException {
        jwtManager.verifyAccessToken(accessToken);

        // where find access token's status, retrieve the DB ??
        AuthenticateResponseModel response = new AuthenticateResponseModel();
        response.setAccessToken(accessToken);
        response.setResult(IDMResults.ACCESS_TOKEN_IS_VALID);
        return response.toResponse();
    }
}
