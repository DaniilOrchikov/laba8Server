package utility;

import ticket.Ticket;
import ticket.TicketBuilder;
import ticket.TicketType;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class SQLTickets {
    private final Connection conn;
    TicketVector tv = new TicketVector();

    public SQLTickets() throws IOException, SQLException {
//        Properties info = new Properties();
//        info.load(new FileInputStream("db.cfg"));
        conn = DriverManager.getConnection("jdbc:postgresql://localhost/ticketLaba", "postgres", "WMZf=7906");
        conn.setAutoCommit(false);
    }

    public void connectToBD() throws SQLException {
        try (Statement stat = conn.createStatement()) {
            try {
                stat.executeUpdate("CREATE TYPE venue_type AS enum ('PUB', 'BAR', 'OPEN_AREA');");
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
            }
            try {
                stat.executeUpdate("CREATE TYPE ticket_type AS enum ('VIP', 'USUAL', 'BUDGETARY', 'CHEAP');");
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
            }
            try (ResultSet rsT = stat.executeQuery("SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name = 'ticket');")) {
                if (rsT.next()) if (!rsT.getBoolean("exists"))
                    stat.executeUpdate("CREATE TABLE ticket (" +
                            "id bigserial PRIMARY KEY, " +
                            "name text NOT NULL , " +
                            "creation_date timestamp NOT NULL DEFAULT NOW(), " +
                            "price integer NOT NULL , " +
                            "type ticket_type NOT NULL , " +
                            "user_name text REFERENCES users(name) ON DELETE CASCADE NOT NULL )");
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
            }
            try (ResultSet rsV = stat.executeQuery("SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name = 'venue');")) {
                if (rsV.next()) if (!rsV.getBoolean("exists"))
                    stat.executeUpdate("CREATE TABLE venue (" +
                            "id bigserial PRIMARY KEY, " +
                            "name text NOT NULL , " +
                            "capacity bigint NOT NULL , " +
                            "type venue_type NOT NULL , " +
                            "ticket_id integer REFERENCES ticket(id) ON DELETE CASCADE NOT NULL)");
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
            }
            try (ResultSet rsA = stat.executeQuery("SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name = 'address');")) {
                if (rsA.next()) if (!rsA.getBoolean("exists"))
                    stat.executeUpdate("CREATE TABLE address (" +
                            "id bigserial PRIMARY KEY, " +
                            "street text NOT NULL , " +
                            "zip_code text NOT NULL ," +
                            "venue_id integer REFERENCES venue(id) ON DELETE CASCADE NOT NULL)");
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
            }
            try (ResultSet rsC = stat.executeQuery("SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name = 'coordinates');")) {
                if (rsC.next()) if (!rsC.getBoolean("exists"))
                    stat.executeUpdate("CREATE TABLE coordinates (" +
                            "id bigserial PRIMARY KEY, " +
                            "x integer NOT NULL , " +
                            "y integer NOT NULL ," +
                            "ticket_id integer REFERENCES ticket(id) ON DELETE CASCADE NOT NULL )");
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
            }
        }
    }

    public String add(TicketBuilder tb) {
        try (PreparedStatement coordinatesStmt = conn.prepareStatement("INSERT INTO coordinates (x, y, ticket_id) VALUES (?, ?, ?)");
             PreparedStatement addressStmt = conn.prepareStatement("INSERT INTO address (street, zip_code, venue_id) VALUES (?, ?, ?)");
             PreparedStatement venueStmt = conn.prepareStatement("INSERT INTO venue (name, capacity, type, ticket_id) VALUES (?, ?, ?, ?) RETURNING id");
             PreparedStatement ticketStmt = conn.prepareStatement("INSERT INTO ticket (name, price, type, user_name) VALUES (?, ?, ?, ?) RETURNING id, creation_date")) {
            Long tId = null;
            ResultSet rs;
            try {
                ticketStmt.setString(1, tb.getName());
                ticketStmt.setInt(2, tb.getPrice());
                ticketStmt.setObject(3, tb.getType().toString(), Types.OTHER);
                ticketStmt.setString(4, tb.getUserName());
                rs = ticketStmt.executeQuery();
                if (rs.next()) {
                    tId = rs.getLong("id");
                    tb.setCreationDate(rs.getTimestamp("creation_date").toLocalDateTime());
                }
            } catch (SQLException e) {
                conn.rollback();
                return "Ошибка при попытке добавить объект в базу данных./" + e.getMessage();
            }
            Long vId = null;
            try {
                venueStmt.setString(1, tb.getName());
                venueStmt.setLong(2, tb.getVenueCapacity());
                venueStmt.setObject(3, tb.getVenueType().toString(), Types.OTHER);
                venueStmt.setLong(4, tId);
                rs = venueStmt.executeQuery();
                if (rs.next()) {
                    vId = rs.getLong("id");
                }
            } catch (SQLException e) {
                conn.rollback();
                return "Ошибка при попытке добавить объект в базу данных./" + e.getMessage();
            }
            try {
                coordinatesStmt.setInt(1, tb.getX());
                coordinatesStmt.setInt(2, tb.getY());
                coordinatesStmt.setLong(3, tId);
                coordinatesStmt.executeUpdate();
            } catch (SQLException e) {
                conn.rollback();
                return "Ошибка при попытке добавить объект в базу данных./" + e.getMessage();
            }
            try {
                addressStmt.setString(1, tb.getAddressStreet());
                addressStmt.setString(2, tb.getAddressZipCode());
                addressStmt.setLong(3, vId);
                addressStmt.executeUpdate();
            } catch (SQLException e) {
                conn.rollback();
                return "Ошибка при попытке добавить объект в базу данных./" + e.getMessage();
            }
            conn.commit();
            tb.setId(tId);
            tv.add(tb.getTicket());
        } catch (SQLException e) {
            return "Ошибка при попытке добавить объект в базу данных./" + e.getMessage();
        }
        return "OK";
    }

    public String addIfMax(TicketBuilder tb) {
        Ticket maxT = tv.maxTicket();
        if (maxT == null) return add(tb);
        if (tb.compareTo(new TicketBuilder(maxT)) > 0) return add(tb);
        return "Объект не добавлен";
    }

    public String addIfMin(TicketBuilder tb) {
        Ticket minT = tv.minTicket();
        if (minT == null) return add(tb);
        if (tb.compareTo(new TicketBuilder(minT)) < 0) return add(tb);
        return "Объект не добавлен";
    }

    public String update(TicketBuilder tb, long id) throws SQLException {
        try (PreparedStatement ticketStatement = conn.prepareStatement("UPDATE ticket SET name = ?, price = ?, type = ? WHERE id = ? AND user_name = ? RETURNING creation_date");
             PreparedStatement venueStatement = conn.prepareStatement("UPDATE venue SET name = ?, capacity = ?, type = ? WHERE ticket_id = ? RETURNING id");
             PreparedStatement addressStatement = conn.prepareStatement("UPDATE address SET street = ?, zip_code = ? WHERE venue_id = ?");
             PreparedStatement coordinatesStatement = conn.prepareStatement("UPDATE coordinates SET x = ?, y = ? WHERE ticket_id = ?")) {
            ticketStatement.setString(1, tb.getName());
            ticketStatement.setInt(2, tb.getPrice());
            ticketStatement.setObject(3, tb.getType(), Types.OTHER);
            ticketStatement.setLong(4, id);
            ticketStatement.setString(5, tb.getUserName());
            ResultSet rs = ticketStatement.executeQuery();
            if (rs.next()) {
                LocalDateTime creationDate = rs.getTimestamp("creation_date").toLocalDateTime();
                Long vId = null;
                venueStatement.setString(1, tb.getName());
                venueStatement.setLong(2, tb.getVenueCapacity());
                venueStatement.setObject(3, tb.getVenueType(), Types.OTHER);
                venueStatement.setLong(4, id);

                rs = venueStatement.executeQuery();
                if (rs.next())
                    vId = rs.getLong("id");

                addressStatement.setString(1, tb.getAddressStreet());
                addressStatement.setString(2, tb.getAddressZipCode());
                addressStatement.setLong(1, vId);

                coordinatesStatement.setInt(1, tb.getX());
                coordinatesStatement.setInt(2, tb.getY());
                coordinatesStatement.setLong(3, id);
                conn.commit();
                tb.setCreationDate(creationDate);
            } else {
                return "Вы не можете обновить данный объект.";
            }
        } catch (SQLException e) {
            conn.rollback();
            return "Ошибка SQL./" + e.getMessage();
        }
        tb.setId(id);
        tv.update(tb.getTicket(), id);
        return "OK";
    }

    public String clear(String userName) throws SQLException {
        try (PreparedStatement preparedStatement = conn.prepareStatement("DELETE FROM ticket WHERE user_name = ? RETURNING id")) {
            preparedStatement.setString(1, userName);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                tv.removeById(rs.getLong("id"));
            }
            conn.commit();
        } catch (SQLException e) {
            conn.rollback();
            return "Ошибка при удалении объектов./" + e.getMessage();
        }
        tv.clearByUser(userName);
        return "OK";
    }

    public String clearAll() {
        try (Statement stat = conn.createStatement()) {
            stat.executeUpdate("TRUNCATE TABLE ticket RESTART IDENTITY CASCADE");
            conn.commit();
        } catch (SQLException e) {
            return e.getMessage();
        }
        tv.clear();
        return "OK";
    }

    public synchronized String remove(int index, String userName) throws SQLException {
        Long id = tv.getIdByIndex(index);
        if (id == -1) return index == 0 ? "Коллекция пустая" : "Индекс выходит за границы коллекции";
        try (PreparedStatement deleteStatement = conn.prepareStatement("DELETE FROM ticket WHERE id = ?");
             PreparedStatement selectStatement = conn.prepareStatement("SELECT EXISTS(SELECT * FROM ticket WHERE id = ? AND user_name = ?)")) {
            selectStatement.setLong(1, id);
            selectStatement.setString(2, userName);
            ResultSet rs = selectStatement.executeQuery();
            if (rs.next() && rs.getBoolean(1)) {
                deleteStatement.setLong(1, id);
                deleteStatement.executeUpdate();
            } else return "access error";
            conn.commit();
        } catch (SQLException e) {
            conn.rollback();
            return "Ошибка при попытке удалить объект из базы данных./" + e.getMessage();
        }
        tv.remove(index);
        return "OK";
    }

    public Ticket[] getAll() {
        return tv.getAll();
    }

    public synchronized String removeLower(TicketBuilder tb) throws SQLException {
        TicketBuilder tb1 = new TicketBuilder();
        List<Long> idL = new ArrayList<>();
        try (PreparedStatement selectIdStatement = conn.prepareStatement("SELECT ticket.id, price, capacity, ticket.type FROM ticket JOIN venue ON venue.ticket_id = ticket.id WHERE user_name = ?");
             PreparedStatement deleteStatement = conn.prepareStatement("DELETE FROM ticket WHERE id = ?")) {
            selectIdStatement.setString(1, tb.getUserName());
            ResultSet rsT = selectIdStatement.executeQuery();
            while (rsT.next()) {
                tb1.clear();
                Long tId = rsT.getLong("id");
                tb1.setPrice(String.valueOf(rsT.getInt("price")));
                tb1.setType(rsT.getString("type"));
                tb1.setVenueCapacity(rsT.getString("capacity"));
                if (tb1.compareTo(tb) < 0) idL.add(tId);
            }
            rsT.close();
            for (Long i : idL) {
                deleteStatement.setLong(1, i);
                deleteStatement.executeUpdate();
            }
            conn.commit();
        } catch (SQLException e) {
            conn.rollback();
            return "Ошибка при взаимодействии с базой данных./" + e.getMessage();
        }
        tb.setId(-1L);
        return String.valueOf(tv.removeLower(tb.getTicket()));
    }

    public synchronized String removeById(long id, String userName) {
        try (PreparedStatement deleteStatement = conn.prepareStatement("DELETE FROM ticket WHERE id = ?");
             PreparedStatement existsStatement = conn.prepareStatement("SELECT EXISTS(SELECT * FROM ticket WHERE id = ? AND user_name = ?)")) {
            existsStatement.setLong(1, id);
            existsStatement.setString(2, userName);
            ResultSet rs = existsStatement.executeQuery();
            if (rs.next() && rs.getBoolean(1)) {
                deleteStatement.setLong(1, id);
                deleteStatement.executeUpdate();
            } else return "Вы не можете удалить этот объект.";
        } catch (SQLException e) {
            return "Ошибка при попытке подключится к базе данных./" + e.getMessage();
        }
        tv.removeById(id);
        return "OK";
    }

    public String getMinByVenue() {
        return tv.getMinByVenue();
    }

    public List<Ticket> filterContainsName(String str) {
        return tv.filterContainsName(str);
    }

    public List<Ticket> filterLessThanPrice(int price) {
        return tv.filterLessThanPrice(price);
    }

    public List<Ticket> filterByPrice(int price) {
        return tv.filterByPrice(price);
    }

    public String getFieldAscendingType() {
        return tv.getFieldAscendingType();
    }

    public long getCountGreaterThanType(TicketType type) {
        return tv.getCountGreaterThanType(type);
    }

    public String getInfo() {
        return tv.getInfo();
    }

    public boolean validId(long id) {
        return tv.validId(id);
    }

    public void exit() throws SQLException {
        conn.close();
    }

    public String loadTickets() throws SQLException {
        String select_query =
                "SELECT ticket.user_name, ticket.id, ticket.name, price, capacity, x, y, ticket.type, svenue.type AS venue_type, users.color, creation_date, street, zip_code FROM ticket " +
                        "JOIN coordinates ON coordinates.ticket_id = ticket.id " +
                        "JOIN (SELECT * FROM venue JOIN address ON address.venue_id = venue.id) AS svenue ON svenue.ticket_id = ticket.id " +
                        "JOIN users ON users.name = ticket.user_name";
        TicketBuilder tb = new TicketBuilder();
        try (PreparedStatement stat = conn.prepareStatement(select_query);
             ResultSet rsT = stat.executeQuery()) {
            while (rsT.next()) {
                tb.clear();
                tb.setUserName(rsT.getString("user_name"));
                tb.setUserColor(rsT.getString("color"));
                tb.setId(rsT.getLong("id"));
                tb.setName(rsT.getString("name"));
                tb.setCreationDate(rsT.getTimestamp("creation_date").toLocalDateTime());
                tb.setPrice(String.valueOf(rsT.getInt("price")));
                tb.setType(rsT.getString("type"));
                tb.setVenueCapacity(rsT.getString("capacity"));
                tb.setVenueType(rsT.getString("venue_type"));
                tb.setAddressStreet(rsT.getString("street"));
                tb.setAddressZipCode(rsT.getString("zip_code"));
                tb.setX(String.valueOf(rsT.getInt("x")));
                tb.setY(String.valueOf(rsT.getInt("y")));
                tv.add(tb.getTicket());
            }
            conn.commit();
            return "OK";
        } catch (SQLException e) {
            conn.rollback();
            return "Ошибка при чтении из базы данных. " + e.getMessage();
        }
    }

    public Long getId() {
        return tv.getId();
    }

    public Long[] getAllValidId(String userName) throws SQLException {
        ArrayList<Long> arr = new ArrayList<>();
        try (PreparedStatement stat = conn.prepareStatement("SELECT id FROM ticket WHERE user_name = ?")) {
            stat.setString(1, userName);
            ResultSet rs = stat.executeQuery();
            while (rs.next()) {
                arr.add(rs.getLong("id"));
            }
        }
        return arr.toArray(new Long[0]);
    }

    public String getCreationDate() {
        return tv.getCreationDate();
    }
    public Ticket get(Long id){
        return tv.get(id);
    }
}
