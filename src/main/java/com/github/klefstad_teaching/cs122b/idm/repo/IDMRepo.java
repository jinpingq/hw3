package com.github.klefstad_teaching.cs122b.idm.repo;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Types;
import java.util.Date;

@Component
public class IDMRepo
{
    private final NamedParameterJdbcTemplate template;

    @Autowired
    public IDMRepo(NamedParameterJdbcTemplate template)
    {
        this.template = template;
    }
    // do sql in workbench
    public NamedParameterJdbcTemplate getTemplate() {
        return template;
    }
    public User searchByEmail(String email) {
        try {
            // expect return only one row
            User user = this.template.queryForObject(
                    "SELECT id, email, user_status_id, salt, hashed_password FROM idm.user WHERE email = :email;",
                    new MapSqlParameterSource()
                            .addValue("email", email, Types.VARCHAR),
                    (rs, rowNum) ->
                            new User()
                                    .setId(rs.getInt("id"))
                                    .setEmail(rs.getString("email"))
                                    .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                    .setSalt(rs.getString("salt"))
                                    .setHashedPassword(rs.getString("hashed_password")));
            return user;
        } catch (DataAccessException e) {
            throw new ResultError(IDMResults.USER_NOT_FOUND);
        }
    }
    public RefreshToken searchByRereshToken(String refreshToken)
    {
        try {
            // expect return only one row
            RefreshToken token = this.template.queryForObject(
                    "SELECT id, token, user_id, token_status_id, expire_time, max_life_time " +
                            "FROM idm.refresh_token " +
                            "WHERE token = :refreshToken;",
                    new MapSqlParameterSource()
                            .addValue("token", refreshToken, Types.INTEGER),
                    (rs, rowNum) ->
                            new RefreshToken()
                                    .setToken(rs.getString("token"))
                                    .setUserId(rs.getInt("user_id"))
                                    .setTokenStatus(TokenStatus.fromId(rs.getInt("token_status_id")))
                                    .setExpireTime(rs.getTimestamp("expire_time"))
                                    .setMaxLifeTime(rs.getTimestamp("max_life_time")));
            return token;
        } catch (DataAccessException e) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_NOT_FOUND);}
    }

    public void insertUser(String email, Integer user_status_id, String salt, String hashed_password)
    {
        try {
            // manipulate database
            this.template.update(
                    "INSERT INTO idm.user (email, user_status_id, salt, hashed_password)" +
                            "VALUES (:email, :user_status_id, :salt, :hashed_password);",
                    new MapSqlParameterSource()
                            .addValue("email", email, Types.VARCHAR)
                            .addValue("user_status_id", user_status_id, Types.INTEGER)
                            .addValue("salt", salt, Types.VARCHAR)
                            .addValue("hashed_password", hashed_password, Types.VARCHAR)
            );
        } catch (DataAccessException e) {
            throw new ResultError(IDMResults.USER_ALREADY_EXISTS);}
    }
    public void insertRefreshToken(RefreshToken refreshToken)
    {
        try {
            // manipulate database
            this.template.update(
                    "INSERT INTO idm.refresh_token (token, user_id, token_status_id, expire_time, max_life_time)" +
                            "VALUES (:token, :user_id, :token_status_id, :expire_time, :max_life_time);",
                    new MapSqlParameterSource()
                            .addValue("token", refreshToken.getToken(), Types.VARCHAR)
                            .addValue("user_id", refreshToken.getUserId(), Types.INTEGER)
                            .addValue("token_status_id", refreshToken.getTokenStatus().id(), Types.INTEGER)
                            .addValue("expire_time", refreshToken.getExpireTime(), Types.TIMESTAMP)
                            .addValue("max_life_time", refreshToken.getMaxLifeTime(), Types.TIMESTAMP)
            );
        } catch (DataAccessException e) {
            throw new ResultError(IDMResults.USER_ALREADY_EXISTS);}
    }

    public void updateRefreshToken(RefreshToken token)
    {
        Integer status_id = token.getTokenStatus().id();
        Integer token_id = token.getId();
        Date expire_time = token.getExpireTime();
        try {
            // manipulate database
            this.template.update(
                    "UPDATE idm.refresh_token " +
                            "SET token_status_id = :status_id, expire_time = :expire_time WHERE id = :token_id;",
                    new MapSqlParameterSource()
                            .addValue("token_status_id", status_id, Types.INTEGER)
                            .addValue("id", token_id, Types.INTEGER)
                            .addValue("expire_time", expire_time, Types.DATE)
                    // Date to Timestamp ? ?
                    // do I need to add more values ??
            );
        } catch (DataAccessException e) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_NOT_FOUND);}
    }


    public User searchById(Integer id) {
        try {
            // expect return only one row
            User user = this.template.queryForObject(
                    "SELECT id, email, user_status_id, salt, hashed_password FROM idm.user WHERE id = :id;",
                    new MapSqlParameterSource()
                            .addValue("id", id, Types.INTEGER),
                    (rs, rowNum) ->
                            new User()
                                    .setId(rs.getInt("id"))
                                    .setEmail(rs.getString("email"))
                                    .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                    .setSalt(rs.getString("salt"))
                                    .setHashedPassword(rs.getString("hashed_password")));
            return user;
        } catch (DataAccessException e) {
            throw new ResultError(IDMResults.USER_NOT_FOUND);
        }
    }

//    public List<User> searchById (Integer id)
//    {
//        try {
//            // return a list
//            List<User> users = this.template.query(
//                    "SELECT id, email, user_status_id, salt, hashed_password" +
//                            "FROM idm.user WHERE id = :id;",
//                    new MapSqlParameterSource()
//                            .addValue("id", email, Types.INTEGER),
//                    (rs, rowNum) ->
//                            new User()
//                                    .setId(rs.getInt("id"))
//                                    .setEmail(rs.getString("email"))
//                                    .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
//                                    .setSalt(rs.getString("salt"))
//                                    .setHashedPassword(rs.getString("hashed_password"))
//
//            return users;
//        )
//        } catch (DataAccessException e) {
//            throw new ResultError(IDMResults.USER_NOT_FOUND);}
//    }
}



