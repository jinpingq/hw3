package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.repo.IDMRepo;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Component
public class IDMAuthenticationManager
{
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String       HASH_FUNCTION = "PBKDF2WithHmacSHA512";

    private static final int ITERATIONS     = 10000;
    private static final int KEY_BIT_LENGTH = 512;

    private static final int SALT_BYTE_LENGTH = 4;

    public final IDMRepo repo;

    @Autowired
    public IDMAuthenticationManager(IDMRepo repo)
    {
        this.repo = repo;
    }

    private static byte[] hashPassword(final char[] password, String salt)
    {
        return hashPassword(password, Base64.getDecoder().decode(salt));
    }

    private static byte[] hashPassword(final char[] password, final byte[] salt)
    {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_FUNCTION);

            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);

            SecretKey key = skf.generateSecret(spec);

            return key.getEncoded();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] genSalt()
    {
        byte[] salt = new byte[SALT_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public User selectAndAuthenticateUser(String email, char[] password)
    {
        User user = repo.searchByEmail(email);

        if (! user.getHashedPassword().equals(hashPassword(password, user.getSalt()))  )
            throw new ResultError(IDMResults.INVALID_CREDENTIALS);
        return user;
    }

    public void createAndInsertUser(String email, char[] password)
    {
        byte[] salt = genSalt();
        byte[] encodedPassword = hashPassword(password, salt);
        String base64EncodedHashedPassword = Base64.getEncoder().encodeToString(encodedPassword);
        String base64EncodedHashedSalt = Base64.getEncoder().encodeToString(salt);

//        User aUser= new User();
        repo.insertUser(email, 1, base64EncodedHashedSalt, base64EncodedHashedPassword);
    }

    public RefreshToken verifyRefreshToken(String token)
    {
        return null;
    }

    public void updateRefreshTokenExpireTime(RefreshToken refreshToken)
    {
        this.repo.getTemplate().update(
                "INSERT INTO idm.refresh_token (token, user_id, token_status_id, expire_time, max_life_time)" +
                        "VALUE (:token, :userId, :tokenStatus, :expireTime, :maxLifeTime",
                new MapSqlParameterSource()
                        .addValue("token", refreshToken.getToken(), java.sql.Types.VARCHAR)
                        .addValue("userId", refreshToken.getUserId(), java.sql.Types.INTEGER)
                        .addValue("tokenStatus", refreshToken.getTokenStatus().id(), java.sql.Types.INTEGER)
                        .addValue("expireTime", refreshToken.getExpireTime(), java.sql.Types.TIMESTAMP)
                        .addValue("maxLifeTime", refreshToken.getMaxLifeTime(), java.sql.Types.TIMESTAMP)
        );
    }

    public void expireRefreshToken(RefreshToken token)
    {
        token.setTokenStatus(TokenStatus.fromId(2));
    }

    public void revokeRefreshToken(RefreshToken token)
    {
        token.setTokenStatus(TokenStatus.fromId(3));
    }

    public User getUserFromRefreshToken(RefreshToken refreshToken)
    {
        Integer userId = refreshToken.getUserId();

        return null;
    }
}
