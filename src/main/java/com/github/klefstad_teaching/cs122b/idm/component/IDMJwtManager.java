package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
// line 91 ??
@Component
public class IDMJwtManager
{
    private final JWTManager jwtManager;

    @Autowired
    public IDMJwtManager(IDMServiceConfig serviceConfig)
    {
        this.jwtManager =
            new JWTManager.Builder()
                .keyFileName(serviceConfig.keyFileName())
                .accessTokenExpire(serviceConfig.accessTokenExpire())
                .maxRefreshTokenLifeTime(serviceConfig.maxRefreshTokenLifeTime())
                .refreshTokenExpire(serviceConfig.refreshTokenExpire())
                .build();

    }

    private SignedJWT buildAndSignJWT(JWTClaimsSet claimsSet)
        throws JOSEException
    {
        JWSHeader header =
                new JWSHeader.Builder(JWTManager.JWS_ALGORITHM)
                        .keyID(jwtManager.getEcKey().getKeyID())
                        .type(JWTManager.JWS_TYPE)
                        .build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(jwtManager.getSigner());
        return signedJWT;
    }



    private void verifyJWT(SignedJWT jwt)
        throws JOSEException, BadJOSEException
    {
        jwt.verify(jwtManager.getVerifier());
        jwtManager.getJwtProcessor().process(jwt, null);

    }



    public String buildAccessToken(User user) throws JOSEException, BadJOSEException {
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject(user.getEmail())
                        .expirationTime(
                                Date.from(
                                        Instant.now().plus(this.jwtManager.getAccessTokenExpire())))
                        .claim(JWTManager.CLAIM_ID, user.getId())
                        .claim(JWTManager.CLAIM_ROLES, user.getRoles())
                        .issueTime(Date.from(Instant.now()))
                        .build();
        SignedJWT signedJWT = buildAndSignJWT(claimsSet);
        verifyJWT(signedJWT);
        // return to user serialize, where put this, where to return?
        String serialized = signedJWT.serialize();
        return serialized;
    }

    public void verifyAccessToken(String jws)
    {

        try {
            SignedJWT rebuiltSignedJwt = SignedJWT.parse(jws);
            rebuiltSignedJwt.verify(jwtManager.getVerifier());
            jwtManager.getJwtProcessor().process(rebuiltSignedJwt, null);
            Date expireTime = rebuiltSignedJwt.getJWTClaimsSet().getExpirationTime();
            if (Instant.now().isAfter(expireTime.toInstant()))
                throw new ResultError(IDMResults.ACCESS_TOKEN_IS_EXPIRED);
        } catch (IllegalStateException | JOSEException | BadJOSEException | ParseException e) {
//            e.printStackTrace();
            throw new ResultError(IDMResults.ACCESS_TOKEN_IS_INVALID);
        }

    }
     //chang User to user_id, only need user_id or we need retrieve user DB to get whole user object
    public RefreshToken buildRefreshToken(Integer user_id)
    {
        RefreshToken refreshToken = new RefreshToken()
                .setToken(generateUUID().toString())
                .setUserId(user_id)
                .setTokenStatus(TokenStatus.fromId(1))
                .setExpireTime(
                        Instant.now().plus(this.jwtManager.getRefreshTokenExpire()))
                .setMaxLifeTime(
                        Instant.now().plus(this.jwtManager.getMaxRefreshTokenLifeTime()));
        return refreshToken;
    }

    public boolean hasExpired(RefreshToken refreshToken)
    {
        Instant now = Instant.now();
        return ((now.isAfter(refreshToken.getExpireTime())) ||
                now.isAfter(refreshToken.getMaxLifeTime()));

    }

    // what this function for ??
    public boolean needsRefresh(RefreshToken refreshToken)
    {
        return false;
    }

    public void updateRefreshTokenExpireTime(RefreshToken refreshToken)
    {
        refreshToken.setExpireTime(
                Instant.now().plus(this.jwtManager.getRefreshTokenExpire()));
    }

    public UUID generateUUID()
    {
        return UUID.randomUUID();
    }
}
