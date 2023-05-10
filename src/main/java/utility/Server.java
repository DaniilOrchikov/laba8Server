package utility;

import ticket.TicketType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ticket.Ticket;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;

/**
 * Класс серверного приложения.
 * <br>Принимает команду от клиентского приложения.
 * <br>Исполняет ее с помощью класса {@link TicketVector}
 * <br>Отправляет ответ обратно клиенту
 */
public class Server {
    public static void main(String[] args) throws SQLException, IOException {
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException ignored) {

            }
        }
        SQLTickets sqlt = new SQLTickets();
        Server serv = new Server(sqlt);
        serv.createTQ();
        serv.mainLoop();
    }

    /**
     * Поле {@link TicketVector}
     */
    private final SQLTickets sqlt;
    /**
     * Поле {@link ServerSocket}, который создает сокеты для общения с клиентом
     */
    private static int port = 5473;
    private final ServerSocket serv;
    private final Authorizer authorizer = new Authorizer();
    /**
     * Поле логгера {@link Logger}
     */
    private static final Logger logger = LogManager.getLogger(Server.class);


    private final ExecutorService requestPool;
    private final ExecutorService processingPool;
    private final ExecutorService responsePool;


    public Server(SQLTickets sqlt) throws IOException, SQLException {
        this.sqlt = sqlt;
        sqlt.connectToBD();
        serv = new ServerSocket(port);
        requestPool = ForkJoinPool.commonPool();
        processingPool = Executors.newFixedThreadPool(10);
        responsePool = ForkJoinPool.commonPool();
    }

    /**
     * Ответ клиенту
     */
    private void response(Answer answer, Socket sock) throws IOException, SQLException {
        ObjectOutputStream oos = new ObjectOutputStream(sock.getOutputStream());
        oos.writeObject(answer);
        sock.close();
    }

    public void connectionAcceptance(Socket sock) {
        logger.info("Установлено подключение. Адрес - " + sock.getRemoteSocketAddress() + ".");
        requestPool.execute(() -> {
            try {
                ObjectInputStream ois = new ObjectInputStream(sock.getInputStream());
                Command command = (Command) ois.readObject();
                logger.info("Получена команда " + String.join(" ", command.getCommand()) + ". От " + sock.getRemoteSocketAddress() + ".");
                processingPool.execute(() -> {
                    Answer answer;
                    try {
                        answer = commandExecution(command);
                    } catch (SQLException e) {
                        throw new RuntimeException(e);
                    }
                    responsePool.execute(() -> {
                        try {
                            response(answer, sock);
                            logger.info("Отправлен ответ " + sock.getRemoteSocketAddress() + ".");
                        } catch (IOException | SQLException e) {
                            throw new RuntimeException(e);
                        }
                    });
                });

            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }
        });
        logger.info(sock.getRemoteSocketAddress() + " отключился.");
    }

    public void mainLoop() throws IOException, SQLException {
        logger.info("Сервер запущен.");
        Runnable accept = () -> {
            while (!Thread.currentThread().isInterrupted()) {
                Socket sock;
                try {
                    sock = serv.accept();
                    connectionAcceptance(sock);
                } catch (IOException e) {
                    break;
                }
            }
        };
        Thread thread = new Thread(accept);
        thread.start();
        while (true) {
            try {
                Scanner in = new Scanner(System.in);
                switch (in.next()) {
                    case ("exit") -> {
                        logger.info("Сервер выключен.");
                        exit(thread);
                    }
                    case ("clear") -> {
                        String resp = sqlt.clearAll();
                        if (resp.equals("OK")) logger.info("Коллекция очищена");
                        else logger.error(resp);
                    }
                }
            } catch (NoSuchElementException err) {
                logger.warn("Экстренное выключение сервера.");
                exit(thread);
            }
        }
    }

    private void exit(Thread thread) throws SQLException, IOException {
        thread.interrupt();
        sqlt.exit();
        processingPool.shutdown();
        serv.close();
        System.exit(0);
    }

    public void createTQ() throws SQLException {
        String resp = sqlt.loadTickets();
        if (resp.equals("OK")) logger.info("Загрузка коллекции из базы данных прошла успешно" + sqlt.getInfo());
        else logger.warn(resp);
    }

    /**
     * Исполнение команд не требующих создания объекта класса {@link Ticket}.<br>
     * Команды - <b>show</b>, <b>clear</b>, <b>remove_first</b>, <b>remove_at</b>, <b>remove_by_id</b>, <b>min_by_venue</b>, <b>filter_contains_name</b>, <b>filter_less_than_price</b>, <b>filter_by_price</b>, <b>save</b>, <b>info</b>, <b>count_greater_than_type</b>, <b>print_field_ascending_type</b>
     *
     * @param command объект класса {@link Command}
     * @return возвращает объект класса {@link Answer} для отправки клиенту
     */
    public Answer commandExecution(Command command) throws SQLException {
        switch (command.getCommand()[0]) {
            case("get"):
                return new Answer(sqlt.get(Long.parseLong(command.getCommand()[1])).toString(), false);
            case ("get_all_valid_id"):
                return new Answer(Arrays.toString(sqlt.getAllValidId(command.getName())), false);
            case ("is_collection_updated"):
                if (sqlt.getId() == Long.parseLong(command.getCommand()[1]))
                    return new Answer("NO", true);
                else
                    return new Answer(sqlt.getId().toString(), true);
            case ("get_tickets_array"):
                StringBuilder str = new StringBuilder();
                Arrays.stream(sqlt.getAll()).forEach(t -> str.append(t).append("\n"));
                return new Answer(str.toString(), false);
            case ("show"):
                str = new StringBuilder();
                Arrays.stream(sqlt.getAll()).map(Ticket::getId).forEach(t -> str.append(t).append(" "));
                return new Answer(str.toString(), false);
            case ("clear"):
                String[] resp = sqlt.clear(command.getName()).split("/");
                if (resp[0].equals("OK")) return new Answer("OK", true);
                else {
                    logger.warn(resp[1]);
                    return new Answer(resp[0], false);
                }
            case ("remove_first"):
                resp = sqlt.remove(0, command.getName()).split("/");
                if (resp[0].equals("OK"))
                    return new Answer("OK", true);
                else {
                    if (resp.length >= 2) {
                        logger.warn(resp[1]);
                    }
                    return new Answer(resp[0], false);
                }
            case ("remove_at"):
                resp = sqlt.remove(Integer.parseInt(command.getCommand()[1]), command.getName()).split("/");
                if (resp[0].equals("OK"))
                    return new Answer("OK", true);
                else {
                    if (resp.length >= 2) {
                        logger.warn(resp[1]);
                    }
                    return new Answer(resp[0], false);
                }
            case ("remove_by_id"):
                long id = Long.parseLong(command.getCommand()[1]);
                if (!sqlt.validId(id))
                    return new Answer("Неверный id", false);
                resp = sqlt.removeById(id, command.getName()).split("/");
                if (resp[0].equals("OK"))
                    return new Answer("OK", true);
                else {
                    if (resp.length >= 2) {
                        logger.warn(resp[1]);
                    }
                    return new Answer(resp[0], false);
                }
            case ("min_by_venue"):
                return new Answer(sqlt.getMinByVenue(), false);
            case ("filter_contains_name"):
                StringBuilder sb = new StringBuilder();
                String name;
                if (command.getCommand().length > 1) name = command.getCommand()[1];
                else name = "";
                for (Ticket t : sqlt.filterContainsName(name)) sb.append(t.toString()).append("\n");
                return new Answer(sb.toString(), false);
            case ("filter_less_than_price"):
                sb = new StringBuilder();
                int price = Integer.parseInt(command.getCommand()[1]);
                for (Ticket t : sqlt.filterLessThanPrice(price)) sb.append(t.toString());
                return new Answer(sb.toString(), false);
            case ("filter_by_price"):
                sb = new StringBuilder();
                price = Integer.parseInt(command.getCommand()[1]);
                for (Ticket t : sqlt.filterByPrice(price)) sb.append(t.toString());
                return new Answer(sb.toString(), false);
            case ("info"):
                return new Answer(sqlt.getInfo(), false);
            case ("count_greater_than_type"):
                return new Answer(String.valueOf(sqlt.getCountGreaterThanType(TicketType.valueOf(command.getCommand()[1]))), false);
            case ("print_field_ascending_type"):
                return new Answer(sqlt.getFieldAscendingType(), false);
            case ("sign_up"):
                resp = authorizer.addUser(command.getName(), command.getPassword()).split("/");
                if (resp[0].equals("OK")) {
                    logger.info("Добавлен новый пользователь - " + command.getName());
                    return new Answer(resp[0] + "/" + resp[1], true);
                } else {
                    if (resp.length == 2) logger.info(resp[1]);
                    return new Answer(resp[0], false);
                }
            case ("sign_in"):
                resp = authorizer.authorize(command.getName(), command.getPassword()).split("/");
                if (resp[0].equals("OK")) {
                    return new Answer(resp[0] + "/" + resp[1], true);
                } else {
                    if (resp.length == 2) logger.info(resp[1]);
                    return new Answer(resp[0], false);
                }
            case ("add"):
                resp = sqlt.add(command.getTicketBuilder()).split("/");
                if (resp[0].equals("OK")) return new Answer("OK", true);
                else {
                    logger.warn(resp[1]);
                    return new Answer(resp[0], false);
                }
            case ("update"):
                id = Long.parseLong(command.getCommand()[1]);
                if (!sqlt.validId(id)) return new Answer("Неверный id", false);
                resp = sqlt.update(command.getTicketBuilder(), id).split("/");
                if (resp[0].equals("OK")) return new Answer("OK", true);
                else {
                    if (resp.length >= 2) {
                        logger.warn(resp[1]);
                    }
                    return new Answer(resp[0], false);
                }
            case ("add_if_max"):
                resp = sqlt.addIfMax(command.getTicketBuilder()).split("/");
                if (resp[0].equals("OK")) return new Answer("OK", true);
                else {
                    return new Answer(resp[0], false);
                }
            case ("add_if_min"):
                resp = sqlt.addIfMin(command.getTicketBuilder()).split("/");
                if (resp[0].equals("OK")) return new Answer("OK", true);
                else {
                    return new Answer(resp[0], false);
                }
            case ("remove_lower"):
                resp = sqlt.removeLower(command.getTicketBuilder()).split("/");
                if (resp[0].matches("^[0-9]+$")) return new Answer(resp[0], false);
                else {
                    logger.info(resp[1]);
                    return new Answer(resp[0], false);
                }
            case("get_creation_date"):
                resp = sqlt.getCreationDate().split("/");
                if (resp[0].equals("OK")) return new Answer("OK", true);
                else {
                    return new Answer(resp[0], false);
                }
        }
        return new Answer("error", false);
    }
}
