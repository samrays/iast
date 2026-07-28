package com.example.app;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Ordinary application code, written the way vulnerable code is actually written.
 *
 * <p>Nothing here knows the agent exists — no annotations, no imports, no hooks. A
 * {@code StringBuilder} and a plain {@code Statement} is precisely the shape of the defect
 * this product is sold to find, and the point of the integration suite is that it is found
 * without the application participating in any way.
 */
public final class UserRepository {

    private final Connection connection;

    public UserRepository(Connection connection) {
        this.connection = connection;
    }

    /** The defect: a request parameter concatenated into SQL. */
    public List<String> findByNameUnsafe(String name) throws SQLException {
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT name FROM users WHERE name = '");
        sql.append(name);
        sql.append("'");

        List<String> results = new ArrayList<>();
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(sql.toString())) {
            while (rows.next()) {
                results.add(rows.getString(1));
            }
        }
        return results;
    }

    /** The same query, bound. Must produce no finding, ever. */
    public List<String> findByNameSafe(String name) throws SQLException {
        List<String> results = new ArrayList<>();
        try (PreparedStatement statement =
                connection.prepareStatement("SELECT name FROM users WHERE name = ?")) {
            statement.setString(1, name);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    results.add(rows.getString(1));
                }
            }
        }
        return results;
    }

    /** Create the table this demo queries. */
    public static void seed(Connection connection) throws SQLException {
        try (Statement setup = connection.createStatement()) {
            setup.execute("CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(64))");
            setup.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob'), (3, 'carol')");
        }
    }
}
