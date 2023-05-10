package utility;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.*;
import java.util.Properties;

public class Authorizer {
    private final Connection conn;

    public Authorizer() throws IOException, SQLException {
//        Properties info = new Properties();
//        info.load(new FileInputStream("db.cfg"));
        conn = DriverManager.getConnection("jdbc:postgresql://localhost/ticketLaba", "postgres", "WMZf=7906");
        conn.setAutoCommit(false);
        try (Statement stat = conn.createStatement()) {
            ResultSet rsV = stat.executeQuery("SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name = 'users')");
            if (rsV.next() && !rsV.getBoolean(1)) {
                stat.executeUpdate("CREATE TABLE users (name text PRIMARY KEY, password text NOT NULL, salt char(10) NOT NULL, color char(6) NOT NULL)");
                conn.commit();
            }
        } catch (SQLException e) {
            conn.rollback();
        }
    }

    public String addUser(String name, String password) throws SQLException {
        String salt = RandomTextGenerator.generate(10);
        String color = RandomTextGenerator.generateColor(6);
        password = PasswordHasher.hashPassword(password, salt);
        try (PreparedStatement userStmt = conn.prepareStatement("INSERT INTO users VALUES (?, ?, ?, ?)");
             PreparedStatement userExist = conn.prepareStatement("SELECT EXISTS(SELECT * FROM users WHERE name = ?)")) {
            userExist.setString(1, name);
            ResultSet rs = userExist.executeQuery();
            if (rs.next() && rs.getBoolean(1)) {
                return "already exists";
            }
            userStmt.setString(1, name);
            userStmt.setString(2, password);
            userStmt.setString(3, salt);
            userStmt.setString(4, color);
            userStmt.executeUpdate();
            conn.commit();
        } catch (SQLException e) {
            conn.rollback();
            return "error/" + e.getMessage();
        }
        return "OK/" + color;
    }

    public String authorize(String name, String password) {
        try (PreparedStatement userStmt = conn.prepareStatement("SELECT salt, password, color FROM users WHERE name = ?")) {
            userStmt.setString(1, name);
            ResultSet rs = userStmt.executeQuery();
            if (rs.next()) {
                String salt = rs.getString("salt");
                String userPassword = rs.getString("password");
                String color = rs.getString("color");
                return userPassword.equals(PasswordHasher.hashPassword(password, salt)) ? "OK/" + color : "password";
            }
            return "login";
        } catch (SQLException e) {
            return "error/" + e.getMessage();
        }
    }
}
