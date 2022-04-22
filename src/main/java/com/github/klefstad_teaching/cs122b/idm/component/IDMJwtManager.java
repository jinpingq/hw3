package com.github.klefstad_teaching.cs122b.idm.component;

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
            rebuiltSignedJwt.getJWTClaimsSet().getExpirationTime();
        } catch (IllegalStateException | JOSEException | BadJOSEException | ParseException e) {
            e.printStackTrace();
            // Throw some result error?
        }
    }

    public RefreshToken buildRefreshToken(User user)
    {
        RefreshToken refreshToken = new RefreshToken()
                .setToken(generateUUID().toString())
                .setUserId(user.getId())
                .setTokenStatus(TokenStatus.fromId(1))
                .setExpireTime(
                        Date.from(Instant.now().plus(this.jwtManager.getRefreshTokenExpire())))
                .setMaxLifeTime(
                        Date.from(Instant.now().plus(this.jwtManager.getMaxRefreshTokenLifeTime())));
        return refreshToken;
    }

    public boolean hasExpired(RefreshToken refreshToken)
    {
        return (Instant.now().isAfter(refreshToken.getExpireTime()));
    }

    public boolean needsRefresh(RefreshToken refreshToken)
    {
        return false;
    }

    public void updateRefreshTokenExpireTime(RefreshToken refreshToken)
    {
        refreshToken.setExpireTime(
                Date.from(Instant.now().plus(this.jwtManager.getRefreshTokenExpire())));
    }

    private UUID generateUUID()
    {
        return UUID.randomUUID();
    }
}
