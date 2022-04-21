package com.github.klefstad_teaching.cs122b.idm.repo;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Types;
import java.util.List;

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

    public User insertUser(String email)
    {
        try {
            // expect return only one row
            User user = this.template.queryForObject(
                    "SELECT id FROM idm.user WHERE email = :email;",
                    new MapSqlParameterSource()
                            .addValue("email", email, Types.VARCHAR),
                    (rs, rowNum) ->
                            new User()
                                    .setId(rs.getInt("id"))
                                    .setEmail(rs.getString("email"))
                                    .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                    .setSalt(rs.getString("salt"))
                                    .setHashedPassword(rs.getString("hashed_password"))
            );
            // return a list
            List<User> users = this.template.query(
                    "SELECT id, email, user_status_id, salt, hashed_password" +
                            "FROM idm.user WHERE email = :email;",
                    new MapSqlParameterSource()
                            .addValue("email", email, Types.VARCHAR),
                    (rs, rowNum) ->
                            new User()
                                    .setId(rs.getInt("id"))
                                    .setEmail(rs.getString("email"))
                                    .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                    .setSalt(rs.getString("salt"))
                                    .setHashedPassword(rs.getString("hashed_password"))
            );

            // manipulate database
            this.template.update(
                    "INSERT INTO idm.user (email, user_status_id, hashed_password)" +
                            "VALUES (:email, :user_status_id, :hashed_password)",
                    new MapSqlParameterSource()
                            .addValue("email", "some@uci.edu", Types.VARCHAR)
                            .addValue("user_status_id", email, Types.INTEGER)
            );
        } catch (DataAccessException e) {
            throw new ResultError(IDMResults.USER_NOT_FOUND);
        }

    }
    public NamedParameterJdbcTemplate getTemplate() {
        return template;
    }
}
