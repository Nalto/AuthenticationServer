package de.nalto.identityServer.persistence.model;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.jspecify.annotations.Nullable;
import org.springframework.core.log.LogMessage;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.provisioning.GroupManager;
import org.springframework.util.Assert;

import java.nio.file.AccessDeniedException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class ExtendedJdbcUserDetailsManager extends ExtendedJdbcDaoImpl implements ExtendedUserDetailsManager, GroupManager, ExtendedUserDetailsPasswordService {

    public static final String DEF_CREATE_USER_SQL = "insert into users (username, password, enabled) values (?,?,?)";
    public static final String DEF_DELETE_USER_SQL = "delete from users where username = ?";
    public static final String DEF_UPDATE_USER_SQL = "update users set password = ?, enabled = ? where username = ?";
    public static final String DEF_INSERT_AUTHORITY_SQL = "insert into authorities (username, authority) values (?,?)";
    public static final String DEF_DELETE_USER_AUTHORITIES_SQL = "delete from authorities where username = ?";
    public static final String DEF_USER_EXISTS_SQL = "select count(*) from users where username = ?";
    public static final String DEF_CHANGE_PASSWORD_SQL = "update users set password = ? where username = ?";
    public static final String DEF_FIND_GROUPS_SQL = "select group_name from groups";
    public static final String DEF_FIND_USERS_IN_GROUP_SQL = "select username from group_members gm, groups g "
            + "where gm.group_id = g.id and g.group_name = ?";
    public static final String DEF_INSERT_GROUP_SQL = "insert into groups (group_name) values (?)";
    public static final String DEF_FIND_GROUP_ID_SQL = "select id from groups where group_name = ?";
    public static final String DEF_INSERT_GROUP_AUTHORITY_SQL = "insert into group_authorities (group_id, authority) values (?,?)";
    public static final String DEF_DELETE_GROUP_SQL = "delete from groups where id = ?";
    public static final String DEF_DELETE_GROUP_AUTHORITIES_SQL = "delete from group_authorities (group_id, authority) values (?,?)";
    public static final String DEF_DELETE_GROUP_MEMBERS_SQL = "delete from group_members where group_id = ?";
    public static final String DEF_RENAME_GROUP_SQL = "update groups set group_name = ? where group_name = ?";
    public static final String DEF_INSERT_GROUP_MEMBER_SQL = "insert into group_members (group_id, username) values (?,?)";
    public static final String DEF_DELETE_GROUP_MEMBER_SQL = "delete from group_members where group_id = ? and username = ?";
    public static final String DEF_GROUP_AUTHORITIES_QUERY_SQL = "select g.id, g.group_name, ga.authority "
            + "from groups g, group_authorities ga " + "where g.group_name = ? " + "and g.id = ga.group_id ";
    public static final String DEF_DELETE_GROUP_AUTHORITY_SQL = "delete from group_authorities where group_id = ? and authority = ?";

    protected final Log logger = LogFactory.getLog(getClass());

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

    private String createUserSql = DEF_CREATE_USER_SQL;
    private String deleteUserSql = DEF_DELETE_USER_SQL;
    private String updateUserSql = DEF_UPDATE_USER_SQL;
    private String createAuthoritySql = DEF_INSERT_AUTHORITY_SQL;
    private String deleteUserAuthoritiesSql = DEF_DELETE_USER_AUTHORITIES_SQL;
    private String userExistsSql = DEF_USER_EXISTS_SQL;
    private String changePasswordSql = DEF_CHANGE_PASSWORD_SQL;
    private String findAllGroupsSql = DEF_FIND_GROUPS_SQL;
    private String findUsersInGroupSql = DEF_FIND_USERS_IN_GROUP_SQL;
    private String insertGroupSql = DEF_INSERT_GROUP_SQL;
    private String findGroupIdSql = DEF_FIND_GROUP_ID_SQL;
    private String insertGroupAuthoritySql = DEF_INSERT_GROUP_AUTHORITY_SQL;
    private String deleteGroupSql = DEF_DELETE_GROUP_SQL;
    private String deleteGroupAuthoritiesSql = DEF_DELETE_GROUP_AUTHORITIES_SQL;
    private String deleteGroupMembersSql = DEF_DELETE_GROUP_MEMBERS_SQL;
    private String renameGroupSql = DEF_RENAME_GROUP_SQL;
    private String insertGroupMemberSql = DEF_INSERT_GROUP_MEMBER_SQL;
    private String deleteGroupMemberSql = DEF_DELETE_GROUP_MEMBER_SQL;
    private String groupAuthoritiesSql = DEF_GROUP_AUTHORITIES_QUERY_SQL;
    private String deleteGroupAuthoritySql = DEF_DELETE_GROUP_AUTHORITY_SQL;

    private @Nullable AuthenticationManager authenticationManager;
    private UserCache userCache = new NullUserCache();
    private RowMapper<ExtendedUserDetails> userDetailsMapper = this::mapToUser;
    private RowMapper<GrantedAuthority> grantedAuthorityMapper = this::mapToGrantedAuthority;
    private boolean enableUpdatePassword = false;

    public ExtendedJdbcUserDetailsManager(JdbcTemplate jdbcTemplate) {
        super(jdbcTemplate);
    }

    public void setUserDetailsMapper(RowMapper<ExtendedUserDetails> mapper) {
        Assert.notNull(mapper, "userDetailsMapper cannot be null");
        this.userDetailsMapper = mapper;
    }

    public void setGrantedAuthorityMapper(RowMapper<GrantedAuthority> mapper) {
        Assert.notNull(mapper, "grantedAuthorityMapper cannot be null");
        this.grantedAuthorityMapper = mapper;
    }

    @Override
    protected List<ExtendedUserDetails> loadUsersByUsername(String username) {
        return this.jdbcTemplate.query(getUsersByUsernameQuery(), this.userDetailsMapper, username);
    }

    private ExtendedUserDetails mapToUser(ResultSet rs, int rowNum) throws SQLException {
        String userName = rs.getString(1);
        String password = rs.getString(2);
        boolean enabled = rs.getBoolean(3);
        boolean accLocked = false;
        boolean accExpired = false;
        boolean credsExpired = false;
        if (rs.getMetaData().getColumnCount() > 3) {
            // NOTE: acc_locked, acc_expired and creds_expired are also to be loaded
            accLocked = rs.getBoolean(4);
            accExpired = rs.getBoolean(5);
            credsExpired = rs.getBoolean(6);
        }
        return new User(userName, password, enabled, !accExpired, !credsExpired, !accLocked, AuthorityUtils.NO_AUTHORITIES);
    }

    public void setEnableUpdatePassword(boolean enableUpdatePassword) {
        this.enableUpdatePassword = enableUpdatePassword;
    }

    @Override
    public ExtendedUserDetails updatePassword(ExtendedUserDetails user, @Nullable String newPassword) {
        if (this.enableUpdatePassword) {
            user.setPassword(newPassword);
            updateUser(user);
            return user;
        }
        return user;
    }

    @Override
    public List<String> findAllGroups() {
        return this.jdbcTemplate.queryForList(this.findAllGroupsSql, String.class)
                .stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public List<String> findUsersInGroup(String groupName) {
        Assert.hasText(groupName, "groupName should have text");
        return this.jdbcTemplate.queryForList(this.findUsersInGroupSql, String.class, groupName)
                .stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public void createGroup(String groupName, List<GrantedAuthority> authorities) {
        Assert.hasText(groupName, "groupName should have text");
        Assert.notNull(authorities, "authorities cannot be null");
        this.logger.debug("Creating new group '" + groupName + "' with authorities "
                + AuthorityUtils.authorityListToSet(authorities));
        this.jdbcTemplate.update(this.insertGroupSql, groupName);
        int groupId = findGroupId(groupName);
        for (GrantedAuthority a : authorities) {
            String authority = a.getAuthority();
            this.jdbcTemplate.update(this.insertGroupAuthoritySql, (ps) -> {
                ps.setInt(1, groupId);
                ps.setString(2, authority);
            });
        }
    }

    @Override
    public void deleteGroup(String groupName) {
        this.logger.debug("Deleting group '" + groupName + "'");
        Assert.hasText(groupName, "groupName should have text");
        int id = findGroupId(groupName);
        PreparedStatementSetter groupIdPSS = (ps) -> ps.setInt(1, id);
        this.jdbcTemplate.update(this.deleteGroupMembersSql, groupIdPSS);
        this.jdbcTemplate.update(this.deleteGroupAuthoritiesSql, groupIdPSS);
        this.jdbcTemplate.update(this.deleteGroupSql, groupIdPSS);
    }

    @Override
    public void renameGroup(String oldName, String newName) {
        this.logger.debug("Changing group name from '" + oldName + "' to '" + newName + "'");
        Assert.hasText(oldName, "oldName should have text");
        Assert.hasText(newName, "newName should have text");
        this.jdbcTemplate.update(this.renameGroupSql, newName, oldName);
    }

    @Override
    public void addUserToGroup(String username, String group) {
        this.logger.debug("Adding user '" + username + "' to group '" + group + "'");
        Assert.hasText(username, "username should have text");
        Assert.hasText(group, "groupName should have text");
        int id = findGroupId(group);
        this.jdbcTemplate.update(this.insertGroupMemberSql, (ps) -> {
            ps.setInt(1, id);
            ps.setString(2, username);
        });
        this.userCache.removeUserFromCache(username);
    }

    @Override
    public void removeUserFromGroup(String username, String groupName) {
        this.logger.debug("Removing user '" + username + "' to group '" + groupName + "'");
        Assert.hasText(username, "username should have text");
        Assert.hasText(groupName, "groupName should have text");
        int id = findGroupId(groupName);
        this.jdbcTemplate.update(this.deleteGroupMemberSql, (ps) -> {
            ps.setInt(1, id);
            ps.setString(2, username);
        });
        this.userCache.removeUserFromCache(username);
    }

    @Override
    public List<GrantedAuthority> findGroupAuthorities(String groupName) {
        this.logger.debug("Loading authorities for group '" + groupName + "'");
        Assert.hasText(groupName, "groupName should have text");
        return this.jdbcTemplate.query(this.groupAuthoritiesSql, this.grantedAuthorityMapper, groupName);
    }

    private GrantedAuthority mapToGrantedAuthority(ResultSet rs, int rowNum) throws SQLException {
        String roleName = getRolePrefix() + rs.getString(3);
        return new SimpleGrantedAuthority(roleName);
    }

    @Override
    public void addGroupAuthority(String groupName, GrantedAuthority authority) {
        this.logger.debug("Adding authority '" + authority + "' to group '" + groupName + "'");
        Assert.hasText(groupName, "groupName should have text");
        Assert.notNull(authority, "authority cannot be null");
        int id = findGroupId(groupName);
        this.jdbcTemplate.update(this.insertGroupAuthoritySql, (ps) -> {
            ps.setInt(1, id);
            ps.setString(2, authority.getAuthority());
        });
    }

    @Override
    public void removeGroupAuthority(String groupName, GrantedAuthority authority) {
        this.logger.debug("Removing authority '" + authority + "' from group '" + groupName + "'");
        Assert.hasText(groupName, "groupName should have text");
        Assert.notNull(authority, "authority cannot be null");
        int id = findGroupId(groupName);
        this.jdbcTemplate.update(this.deleteGroupAuthoritySql, (ps) -> {
            ps.setInt(1, id);
            ps.setString(2, authority.getAuthority());
        });
    }

    private int findGroupId(String group) {
        Integer groupId = this.jdbcTemplate.queryForObject(this.findGroupIdSql, Integer.class, group);
        if (groupId == null) {
            throw new EmptyResultDataAccessException("Could not find required group '" + group + "'", 1);
        }
        return groupId;
    }

    @Override
    public void createUser(ExtendedUserDetails user) {
        validateUserDetails(user);
        this.jdbcTemplate.update(this.createUserSql, (ps) -> {
            ps.setString(1, user.getUsername());
            ps.setString(2, user.getPassword());
            ps.setBoolean(3, user.isEnabled());
            int paramCount = ps.getParameterMetaData().getParameterCount();
            if (paramCount > 3) {
                // NOTE: acc_locked, acc_expired and creds_expired are also to be inserted
                ps.setBoolean(4, !user.isAccountNonLocked());
                ps.setBoolean(5, !user.isAccountNonExpired());
                ps.setBoolean(6, !user.isCredentialsNonExpired());
            }
        });
        if (getEnableAuthorities()) {
            insertUserAuthorities(user);
        }
    }

    private void insertUserAuthorities(UserDetails user) {
        for (GrantedAuthority auth : user.getAuthorities()) {
            this.jdbcTemplate.update(this.createAuthoritySql, user.getUsername(), auth.getAuthority());
        }
    }

    @Override
    public void updateUser(ExtendedUserDetails user) {
        validateUserDetails(user);
        this.jdbcTemplate.update(this.updateUserSql, (ps) -> {
            ps.setString(1, user.getPassword());
            ps.setBoolean(2, user.isEnabled());
            if (ps.getParameterMetaData().getParameterCount() == 3) {
                ps.setString(3, user.getUsername());
            }
            else {
                // NOTE: acc_locked, acc_expired and creds_expired are also updated
                ps.setBoolean(3, !user.isAccountNonLocked());
                ps.setBoolean(4, !user.isAccountNonExpired());
                ps.setBoolean(5, !user.isCredentialsNonExpired());
                ps.setString(6, user.getUsername());
            }
        });
        if (getEnableAuthorities()) {
            deleteUserAuthorities(user.getUsername());
            insertUserAuthorities(user);
        }
        this.userCache.removeUserFromCache(user.getUsername());
    }

    @Override
    public void deleteUser(String username) {
        if (getEnableAuthorities()) {
            deleteUserAuthorities(username);
        }
        this.jdbcTemplate.update(this.deleteUserSql, username);
        this.userCache.removeUserFromCache(username);
    }

    private void deleteUserAuthorities(String username) {
        this.jdbcTemplate.update(this.deleteUserAuthoritiesSql, username);
    }

    @Override
    public void changePassword(@Nullable String oldPassword, @Nullable String newPassword) throws AuthenticationException, AccessDeniedException {
        Authentication currentUser = this.securityContextHolderStrategy.getContext().getAuthentication();
        if (currentUser == null) {
            throw new AccessDeniedException("Can't change password as no Authentication object found in context for current user.");
        }
        String username = currentUser.getName();
        // If an authentication manager has been set, re-authenticate the user with the supplied password.
        if (this.authenticationManager != null) {
            this.logger.debug(LogMessage.format("Reauthenticating user '%s' for password change request.", username));
            this.authenticationManager.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, oldPassword));
        }
        else {
            this.logger.debug("No authentication manager set. Password won't be re-checked.");
        }
        this.logger.debug("Changing password for user '" + username + "'");
        this.jdbcTemplate.update(this.changePasswordSql, newPassword, username);
        Authentication authentication = createNewAuthentication(currentUser, newPassword);
        SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        this.securityContextHolderStrategy.setContext(context);
        this.userCache.removeUserFromCache(username);
    }

    protected Authentication createNewAuthentication(Authentication currentAuth, @Nullable String newPassword) {
        ExtendedUserDetails user = loadUserByUsername(currentAuth.getName());
        UsernamePasswordAuthenticationToken newAuthentication = UsernamePasswordAuthenticationToken.authenticated(user,
                null, user.getAuthorities());
        newAuthentication.setDetails(currentAuth.getDetails());
        return newAuthentication;
    }

    @Override
    public boolean userExists(String username) {
        Integer usersCount = this.jdbcTemplate.queryForObject(this.userExistsSql, Integer.class, username);
        if (usersCount == null || usersCount > 1) {
            throw new IncorrectResultSizeDataAccessException("[" + usersCount + "] users found with name '"
                    + username + "', expected 1", 1);
        }
        return usersCount == 1;
    }

    private void validateUserDetails(UserDetails user) {
        Assert.hasText(user.getUsername(), "Username may not be empty or null");
        validateAuthorities(user.getAuthorities());
    }

    private void validateAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Assert.notNull(authorities, "Authorities list must not be null");
        for (GrantedAuthority authority : authorities) {
            Assert.notNull(authority, "Authorities list contains a null entry");
            Assert.hasText(authority.getAuthority(), "getAuthority() method must return a non-empty string");
        }
    }
}
