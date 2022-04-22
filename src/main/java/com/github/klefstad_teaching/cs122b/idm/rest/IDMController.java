package com.github.klefstad_teaching.cs122b.idm.rest;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.model.request.LoginRequestModel;
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
        String ePattern = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(ePattern);
        java.util.regex.Matcher m = p.matcher(email);
        if (! m.matches())
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
        if (! Pattern.matches("[a-zA-Z0-9]|[@]|[.]{6,32}", email))
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH);
    }
    private void validatePassword(String password)
    {
        String ePattern = "^[A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(ePattern);
        java.util.regex.Matcher m = p.matcher(password);
        if (! m.matches())
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
        if (! Pattern.matches("[a-zA-Z0-9]{10,20}", password))
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseModel> login(
            @RequestBody LoginRequestModel request) throws BadJOSEException, JOSEException {
        // Input validate here, throw error
        validateEmail(request.getEmail());
        validatePassword(request.getPassword().toString());
        User user = authManager.selectAndAuthenticateUser(request.getEmail(), request.getPassword());
        LoginResponseModel response = new LoginResponseModel();
        response.setAccessToken(jwtManager.buildAccessToken(user));
        response.setRefreshToken(jwtManager.buildRefreshToken(user).getToken());
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
    public ResponseEntity<RegisterResponseModel> refresh(
            @RequestParam("refreshToken")String refreshToken) throws BadJOSEException, JOSEException {
        // Input validate here, throw error
        validateRefreshToken(refreshToken);
        RefreshToken token = authManager.repo.searchByRereshToken(refreshToken);
        if (jwtManager.hasExpired(token))
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_EXPIRED);
        // DOUBLE CHECK HERE!!!
        if (token.getTokenStatus() == TokenStatus.fromId(3))
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_REVOKED);
        LoginResponseModel response = new LoginResponseModel();

        // update table
        response.setRefreshToken(jwtManager.buildAccessToken(user))
        response.setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN);

        return response.toResponse();
    }

}
