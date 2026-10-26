package de.nalto.identityServer.persistence.model;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import java.util.*;

public class ExtendedJdbcDaoImpl implements UserDetailsService, MessageSourceAware {

    public static final String DEF_USERS_BY_USERNAME_QUERY = "select username, password, enabled "
        + "from users "
        + "where username = ?";

    public static final String DEF_AUTHORITIES_BY_USERNAME_QUERY = "select username, authority "
            + "from authorities "
            + "where username = ?";

    public static final String DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY = "select g.id, g.group_name, ga.authority "
            + "from groups g, group_members gm, group_authorities ga "
            + "where gm.username = ? " + "and g.id = ga.group_id " + "and g.id = gm.group_id";

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private String authoritiesByUsernameQuery;
    private String groupAuthoritiesByUsernameQuery;
    private String usersByUsernameQuery;
    private String rolePrefix = "";
    private boolean usernameBasedPrimaryKey = true;
    private boolean enableAuthorities = true;
    private boolean enableGroups;

    protected JdbcTemplate jdbcTemplate;

    /** Logger available to subclasses. */
    protected final Log logger = LogFactory.getLog(getClass());

    public ExtendedJdbcDaoImpl(JdbcTemplate jdbcTemplate) {
        this.usersByUsernameQuery = DEF_USERS_BY_USERNAME_QUERY;
        this.authoritiesByUsernameQuery = DEF_AUTHORITIES_BY_USERNAME_QUERY;
        this.groupAuthoritiesByUsernameQuery = DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY;

        this.jdbcTemplate = jdbcTemplate;
    }

    protected MessageSourceAccessor getMessages() {
        return this.messages;
    }

    protected void addCustomAuthorities(String username, List<GrantedAuthority> authorities) {
    }

    public String getUsersByUsernameQuery() {
        return this.usersByUsernameQuery;
    }

    @Override
    public ExtendedUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<ExtendedUserDetails> users = loadUsersByUsername(username);
        if (users.isEmpty()) {
            this.logger.debug("Query returned no results for user '" + username +"'");
            throw new UsernameNotFoundException(this.messages.getMessage("ExtendedJdbcDaoImpl.notFound",
                    new Object[]{username}, "Username {0} not found"));
        }
        ExtendedUserDetails user = users.get(0); // contains no GrantedAuthority[]
        Set<GrantedAuthority> dbAuthsSet = new HashSet<>();
        if (this.enableAuthorities) {
            dbAuthsSet.addAll(loadUserAuthorities(user.getUsername()));
        }
        if (this.enableGroups) {
            dbAuthsSet.addAll(loadGroupAuthorities(user.getUsername()));
        }
        List<GrantedAuthority> dbAuths = new ArrayList<>(dbAuthsSet);
        addCustomAuthorities(user.getUsername(), dbAuths);
        if (dbAuths.isEmpty()) {
            this.logger.debug("User '" + username + "' has no authorities and will be treated as 'not found'");
            throw new UsernameNotFoundException(this.messages.getMessage("ExtendedJdbcDaoImpl.noAuthority",
                    new Object[]{username}, "User {0} has no GrantedAuthority"));
        }
        return createUserDetails(username, user, dbAuths);
    }

    protected List<ExtendedUserDetails> loadUsersByUsername(String username) {
        RowMapper<ExtendedUserDetails> mapper = (rs, rowNum) -> {
            String username1 = rs.getString(1);
            String password = rs.getString(2);
            boolean enabled = rs.getBoolean(3);
            return new User(username1, password, enabled, true, true, true, Collections.EMPTY_LIST);
        };

        return this.jdbcTemplate.query(this.usersByUsernameQuery, mapper, username);
    }

    protected List<GrantedAuthority> loadUserAuthorities(String username) {
        return this.jdbcTemplate.query(this.authoritiesByUsernameQuery, (rs, rowNum) -> {
            String roleName = ExtendedJdbcDaoImpl.this.rolePrefix + rs.getString(2);
            return new SimpleGrantedAuthority(roleName);
        }, username);
    }

    protected List<GrantedAuthority> loadGroupAuthorities(String username) {
        return this.jdbcTemplate.query(this.groupAuthoritiesByUsernameQuery, (rs, rowNum) -> {
            String roleName = getRolePrefix() + rs.getString(3);
            return new SimpleGrantedAuthority(roleName);
        }, username);
    }

    protected ExtendedUserDetails createUserDetails(String username, ExtendedUserDetails userFromUserQuery,
                                                    List<GrantedAuthority> combinedAuthorities) {
        String returnUsername = userFromUserQuery.getUsername();
        if (!this.usernameBasedPrimaryKey) {
            returnUsername = username;
        }
        return new User(returnUsername, userFromUserQuery.getPassword(), userFromUserQuery.isEnabled(),
                userFromUserQuery.isAccountNonExpired(), userFromUserQuery.isCredentialsNonExpired(),
                userFromUserQuery.isAccountNonLocked(), combinedAuthorities);
    }

    public void setAuthoritiesByUsernameQuery(String queryString) {
        this.authoritiesByUsernameQuery = queryString;
    }

    protected String getAuthoritiesByUsernameQuery() {
        return this.authoritiesByUsernameQuery;
    }

    public void setGroupAuthoritiesByUsernameQuery(String queryString) {
        this.groupAuthoritiesByUsernameQuery = queryString;
    }

    public void setRolePrefix(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    protected String getRolePrefix() {
        return this.rolePrefix;
    }

    protected boolean isUsernameBasedPrimaryKey() {
        return this.usernameBasedPrimaryKey;
    }

    public void setUsersByUsernameQuery(String usersByUsernameQueryString) {
        this.usersByUsernameQuery = usersByUsernameQueryString;
    }

    protected boolean getEnableAuthorities() {
        return this.enableAuthorities;
    }

    public void setEnableAuthorities(boolean enableAuthorities) {
        this.enableAuthorities = enableAuthorities;
    }

    public void setEnableGroups(boolean enableGroups) {
        this.enableGroups = enableGroups;
    }

    public void setUsernameBasedPrimaryKey(boolean usernameBasedPrimaryKey) {
        this.usernameBasedPrimaryKey = usernameBasedPrimaryKey;
    }

    @Override
    public void setMessageSource(MessageSource messageSource) {
        Assert.notNull(messageSource, "messageSource must not be null");
        this.messages = new MessageSourceAccessor(messageSource);
    }

}
